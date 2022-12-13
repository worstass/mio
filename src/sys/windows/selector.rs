use super::Event;
use crate::sys::Events;

cfg_net! {
    use crate::Interest;
}

use super::iocp::{CompletionPort, CompletionStatus};
use std::collections::VecDeque;
use std::ffi::c_void;
use std::io;
use std::os::windows::io::RawSocket;
use std::pin::Pin;
#[cfg(debug_assertions)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// MARKER
use std::ptr;
use std::thread;
use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, WAIT_TIMEOUT};
use windows_sys::Win32::System::IO::OVERLAPPED;
use windows_sys::Win32::Networking::WinSock::{
    ioctlsocket, WSACreateEvent, WSAEventSelect, WSAWaitForMultipleEvents, WSAEnumNetworkEvents,
    SOCKET, WSA_INVALID_HANDLE, FIONBIO,
    WSANETWORKEVENTS, WSA_INFINITE, WSA_WAIT_FAILED,
    FD_WRITE, FD_READ, FD_ACCEPT, FD_CLOSE, FD_CONNECT, FD_CONNECT_BIT, FD_CLOSE_BIT,
};

use windows_sys::Win32::System::Threading::{CreateEventA, SetEvent};

#[derive(Debug)]
struct Win32Event(HANDLE);

unsafe impl Send for Win32Event {}

unsafe impl Sync for Win32Event {}

impl Win32Event {
    fn new() -> io::Result<Win32Event> {
        let event = unsafe {
            CreateEventA(
                ptr::null_mut(), /* no security attributes */
                0, /* not manual reset */
                0, /* initially unset */
                ptr::null(), /* unnamed */
            )
        };
        if event == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Win32Event(event))
        }
    }

    fn set(&self) -> io::Result<()> {
        if unsafe { SetEvent(self.0) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl Drop for Win32Event {
    fn drop(&mut self) {
        // ignore error
        unsafe { CloseHandle(self.0) };
    }
}

#[derive(Debug)]
pub struct SockState {
    cp: Arc<CompletionPort>,
    raw_socket: RawSocket,
    token: Token,
    interests: u32,
    pending: u32,
    /// Used to notify the thread to update its event flags, or possibly quit
    notify_event: Arc<Win32Event>,
    shutdown: bool,
}

impl SockState {
    // This is the function called from the overlapped using as Arc<Mutex<SockState>>. Watch out for reference counting.
    fn feed_event(&mut self) -> Option<Event> {
        if self.pending != 0 && !self.shutdown {
            let flags = self.pending;
            self.pending = 0;
            Some(Event {
                flags,
                data: self.token.0 as u64,
            })
        } else {
            None
        }
    }

    pub fn mark_delete(&mut self) {
        if !self.shutdown {
            self.shutdown = true;
            self.notify_event.set().expect("SetEvent failed");
            // Detach the socket from the socket event.
            if unsafe { WSAEventSelect(self.raw_socket as SOCKET, 0 /*ptr::null_mut()*/, 0) }
                == SOCKET_ERROR
            {
                log::error!("WSAEventSelect failed: {:?}", io::Error::last_os_error());
            }
            // Attempt to re-mark the socket non-blocking. This resets the
            // cached edge triggers in case the socket is later registered
            // again.
            if unsafe {
                ioctlsocket(self.raw_socket as SOCKET, FIONBIO, &mut 1)
            } != 0 {
                log::error!("ioctl(FIONBIO) failed: {:?}", io::Error::last_os_error());
            }
        }
    }
}

cfg_io_source! {
    impl SockState {
        fn new(
            raw_socket: RawSocket,
            token: Token,
            interests: Interest,
            cp: Arc<CompletionPort>,
        ) -> io::Result<SockState> {
            Ok(SockState {
                cp,
                raw_socket,
                token,
                interests:  interests_to_flags(interests),
                pending: 0,
                notify_event: Arc::new(Win32Event::new()?),
                shutdown: false,
            })
        }

        fn start_poll_thread(&mut self, self_arc: &Pin<Arc<Mutex<SockState>>>) -> io::Result<()> {
            assert!(!self.shutdown);
            let notify_event = self.notify_event.clone();

            let socket_event = unsafe { WSACreateEvent() };
            if socket_event == WSA_INVALID_HANDLE as HANDLE {
                return Err(io::Error::last_os_error());
            }
            let socket_event = Win32Event(socket_event);

            let raw_socket = self.raw_socket;
            let self_arc = self_arc.clone();
            thread::spawn(move || {
                let mut guard = self_arc.lock().unwrap();
                if guard.shutdown {
                    return;
                }

                loop {
                    let interests = guard.interests;
                    let mut event_flags = 0u32;
                    if (interests & POLL_SEND) != 0 {
                        event_flags |= FD_WRITE;
                    }
                    if (interests & POLL_RECEIVE) != 0 {
                        event_flags |= FD_READ;
                    }
                    if (interests & POLL_ACCEPT) != 0 {
                        event_flags |= FD_ACCEPT;
                    }
                    if (interests & (POLL_ABORT | POLL_DISCONNECT)) != 0 {
                        event_flags |= FD_CLOSE;
                    }
                    if (interests & (POLL_SEND | POLL_CONNECT_FAIL)) != 0 {
                        event_flags |= FD_CONNECT;
                    }
                    let event_flags = event_flags as i32;
                    if unsafe { WSAEventSelect(raw_socket as SOCKET, socket_event.0, event_flags) }
                        == SOCKET_ERROR
                    {
                        log::error!("WSAEventSelect failed: {:?}", io::Error::last_os_error());
                        return;
                    }

                    drop(guard);

                    let events = [notify_event.0, socket_event.0];
                    if unsafe {
                        WSAWaitForMultipleEvents(
                            events.len() as u32,
                            &events as *const [_; 2] as *const _,
                            0, /* fWaitAll */
                            WSA_INFINITE,
                            0, /* fAlertable */
                        )
                    } == WSA_WAIT_FAILED
                    {
                        log::error!(
                            "WSAWaitForMultipleEvents failed: {:?}",
                            io::Error::last_os_error()
                        );
                        return;
                    }

                    // Before doing anything else, check if we need to stop.
                    guard = self_arc.lock().unwrap();
                    if guard.shutdown {
                        return;
                    }
                    // Read events.
                    let mut events: WSANETWORKEVENTS = unsafe { std::mem::zeroed() };
                    if unsafe {
                        WSAEnumNetworkEvents(
                            raw_socket as SOCKET,
                            socket_event.0,
                            &mut events as *mut _,
                        )
                    } == SOCKET_ERROR
                    {
                        log::error!(
                            "WSAEnumNetworkEvents failed: {:?}",
                            io::Error::last_os_error()
                        );
                        return;
                    }
                    let mut translated_events = 0;
                    let lne = events.lNetworkEvents as u32;
                    if (lne & FD_WRITE) != 0 {
                        translated_events |= POLL_SEND;
                    }
                    if (lne & FD_READ) != 0 {
                        translated_events |= POLL_RECEIVE;
                    }
                    if (lne & FD_ACCEPT) != 0 {
                        translated_events |= POLL_ACCEPT;
                    }
                    if (lne & FD_CLOSE) != 0 {
                        if events.iErrorCode[FD_CLOSE_BIT as usize] != 0 {
                            translated_events |= POLL_ABORT;
                        } else {
                            translated_events |= POLL_DISCONNECT;
                        }
                    }
                    if (lne & FD_CONNECT) != 0 {
                        if events.iErrorCode[FD_CONNECT_BIT as usize] != 0 {
                            translated_events |= POLL_CONNECT_FAIL;
                        } else {
                            translated_events |= POLL_SEND;
                        }
                    }

                    // restrict our attention to events that are still requested
                    translated_events &= guard.interests;

                    // clear interest for this event
                    guard.interests &= !translated_events;
                    guard.pending |= translated_events;

                    // signal the main event loop
                    let overlapped = into_overlapped(self_arc.clone()) as *mut _;
                    if let Err(e) = guard
                        .cp
                        .post(CompletionStatus::new(0, guard.token.0, overlapped))
                    {
                        log::error!("CompletionPort::post error: {:?}", e);
                        break;
                    }
                }
            });
            Ok(())
        }

      fn reregister(&mut self, token: Token, interests: Interest) -> io::Result<()> {
            self.token = token;
            let flags = interests_to_flags(interests);
            let old = self.interests;
            self.interests = flags;
            // If there are queued events that are no longer desired, discard them.
            self.pending &= flags;
            if self.interests != old {
                self.notify_event.set()?;
            }
            Ok(())
        }
    }
}

impl Drop for SockState {
    fn drop(&mut self) {
        self.mark_delete();
    }
}

/// Converts the pointer to a `SockState` into a raw pointer.
/// To revert see `from_overlapped`.
fn into_overlapped(sock_state: Pin<Arc<Mutex<SockState>>>) -> *mut c_void {
    let overlapped_ptr: *const Mutex<SockState> =
        unsafe { Arc::into_raw(Pin::into_inner_unchecked(sock_state)) };
    overlapped_ptr as *mut _
}

/// Convert a raw overlapped pointer into a reference to `SockState`.
/// Reverts `into_overlapped`.
fn from_overlapped(ptr: *mut OVERLAPPED) -> Pin<Arc<Mutex<SockState>>> {
    let sock_ptr: *const Mutex<SockState> = ptr as *const _;
    unsafe { Pin::new_unchecked(Arc::from_raw(sock_ptr)) }
}

/// Each Selector has a globally unique(ish) ID associated with it. This ID
/// gets tracked by `TcpStream`, `TcpListener`, etc... when they are first
/// registered with the `Selector`. If a type that is previously associated with
/// a `Selector` attempts to register itself with a different `Selector`, the
/// operation will return with an error. This matches windows behavior.
#[cfg(debug_assertions)]
static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

/// Windows implementaion of `sys::Selector`
///
/// Edge-triggered event notification is simulated by resetting internal event flag of each socket state `SockState`
/// and setting all events back by intercepting all requests that could cause `io::ErrorKind::WouldBlock` happening.
///
/// This selector is currently only support socket due to `Afd` driver is winsock2 specific.
#[derive(Debug)]
pub struct Selector {
    #[cfg(debug_assertions)]
    id: usize,
    pub(super) inner: Arc<SelectorInner>,
    #[cfg(debug_assertions)]
    has_waker: AtomicBool,
}

impl Selector {
    pub fn new() -> io::Result<Selector> {
        SelectorInner::new().map(|inner| {
            #[cfg(debug_assertions)]
                let id = NEXT_ID.fetch_add(1, Ordering::Relaxed) + 1;
            Selector {
                #[cfg(debug_assertions)]
                id,
                inner: Arc::new(inner),
                #[cfg(debug_assertions)]
                has_waker: AtomicBool::new(false),
            }
        })
    }

    pub fn try_clone(&self) -> io::Result<Selector> {
        Ok(Selector {
            #[cfg(debug_assertions)]
            id: self.id,
            inner: Arc::clone(&self.inner),
            #[cfg(debug_assertions)]
            has_waker: AtomicBool::new(self.has_waker.load(Ordering::Acquire)),
        })
    }

    /// # Safety
    ///
    /// This requires a mutable reference to self because only a single thread
    /// can poll IOCP at a time.
    pub fn select(&mut self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.select(events, timeout)
    }

    #[cfg(debug_assertions)]
    pub fn register_waker(&self) -> bool {
        self.has_waker.swap(true, Ordering::AcqRel)
    }

    pub(super) fn clone_port(&self) -> Arc<CompletionPort> {
        self.inner.cp.clone()
    }

    #[cfg(feature = "os-ext")]
    pub(super) fn same_port(&self, other: &Arc<CompletionPort>) -> bool {
        Arc::ptr_eq(&self.inner.cp, other)
    }
}

cfg_io_source! {
    use super::InternalState;
    use crate::Token;

    impl Selector {
        pub(super) fn register(
            &self,
            socket: RawSocket,
            token: Token,
            interests: Interest,
        ) -> io::Result<InternalState> {
            SelectorInner::register(&self.inner, socket, token, interests)
        }

        pub(super) fn reregister(
            &self,
            state: Pin<Arc<Mutex<SockState>>>,
            token: Token,
            interests: Interest,
        ) -> io::Result<()> {
            self.inner.reregister(state, token, interests)
        }

        #[cfg(debug_assertions)]
        pub fn id(&self) -> usize {
            self.id
        }
    }
}

#[derive(Debug)]
pub struct SelectorInner {
    cp: Arc<CompletionPort>,
    update_queue: Mutex<VecDeque<Pin<Arc<Mutex<SockState>>>>>,
    is_polling: AtomicBool,
}

// We have ensured thread safety by introducing lock manually.
unsafe impl Sync for SelectorInner {}

impl SelectorInner {
    pub fn new() -> io::Result<SelectorInner> {
        CompletionPort::new(0).map(|cp| {
            let cp = Arc::new(cp);
            SelectorInner {
                cp,
                update_queue: Mutex::new(VecDeque::new()),
                is_polling: AtomicBool::new(false),
            }
        })
    }

    /// # Safety
    ///
    /// May only be calling via `Selector::select`.
    pub fn select(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        events.clear();

        if timeout.is_none() {
            loop {
                let len = self.select2(&mut events.statuses, &mut events.events, None)?;
                if len == 0 {
                    continue;
                }
                break Ok(());
            }
        } else {
            self.select2(&mut events.statuses, &mut events.events, timeout)?;
            Ok(())
        }
    }

    pub fn select2(
        &self,
        statuses: &mut [CompletionStatus],
        events: &mut Vec<Event>,
        timeout: Option<Duration>,
    ) -> io::Result<usize> {
        assert_eq!(self.is_polling.swap(true, Ordering::AcqRel), false);

        let result = self.cp.get_many(statuses, timeout);

        self.is_polling.store(false, Ordering::Relaxed);

        match result {
            Ok(iocp_events) => Ok(unsafe { self.feed_events(events, iocp_events) }),
            Err(ref e) if e.raw_os_error() == Some(WAIT_TIMEOUT as i32) => Ok(0),
            Err(e) => Err(e),
        }
    }

    // It returns processed count of iocp_events rather than the events itself.
    unsafe fn feed_events(
        &self,
        events: &mut Vec<Event>,
        iocp_events: &[CompletionStatus],
    ) -> usize {
        let mut n = 0;
        let mut update_queue = self.update_queue.lock().unwrap();
        for iocp_event in iocp_events.iter() {
            if iocp_event.overlapped().is_null() {
                // `Waker` event, we'll add a readable event to match the other platforms.
                events.push(Event {
                    flags: POLL_RECEIVE,
                    data: iocp_event.token() as u64,
                });
                n += 1;
                continue;
            }
            let sock_state = from_overlapped(iocp_event.overlapped());
            let mut sock_guard = sock_state.lock().unwrap();
            if let Some(e) = sock_guard.feed_event() {
                events.push(e);
                n += 1;
            }
        }
        n
    }
}

cfg_io_source! {
    use std::mem::size_of;
    use std::ptr::null_mut;

    use windows_sys::Win32::Networking::WinSock::{
        WSAGetLastError, WSAIoctl, SIO_BASE_HANDLE, SIO_BSP_HANDLE,
        SIO_BSP_HANDLE_POLL, SIO_BSP_HANDLE_SELECT, SOCKET_ERROR,
    };


    impl SelectorInner {
        fn register(
            this: &Arc<Self>,
            socket: RawSocket,
            token: Token,
            interests: Interest,
        ) -> io::Result<InternalState> {
            let flags = interests_to_flags(interests);

            let sock = {
                let sock = Arc::pin(Mutex::new(SockState::new(
                    socket,
                    token,
                    interests,
                    this.cp.clone(),
                )?));

                let event = Event {
                    flags,
                    data: token.0 as u64,
                };
                sock.lock()
                    .unwrap()
                    .start_poll_thread(&sock)?;
                sock
            };

            let state = InternalState {
                selector: this.clone(),
                token,
                interests,
                sock_state: sock.clone(),
            };

            Ok(state)
        }

        // Directly accessed in `IoSourceState::do_io`.
        pub(super) fn reregister(
            &self,
            state: Pin<Arc<Mutex<SockState>>>,
            token: Token,
            interests: Interest,
        ) -> io::Result<()> {
            let mut state_guard = state.lock().unwrap();
            state_guard.reregister(token, interests)
        }
    }

    fn try_get_base_socket(raw_socket: RawSocket, ioctl: u32) -> Result<RawSocket, i32> {
        let mut base_socket: RawSocket = 0;
        let mut bytes: u32 = 0;
        unsafe {
            if WSAIoctl(
                raw_socket as usize,
                ioctl,
                null_mut(),
                0,
                &mut base_socket as *mut _ as *mut c_void,
                size_of::<RawSocket>() as u32,
                &mut bytes,
                null_mut(),
                None,
            ) != SOCKET_ERROR
            {
                Ok(base_socket)
            } else {
                Err(WSAGetLastError())
            }
        }
    }

    fn get_base_socket(raw_socket: RawSocket) -> io::Result<RawSocket> {
        let res = try_get_base_socket(raw_socket, SIO_BASE_HANDLE);
        if let Ok(base_socket) = res {
            return Ok(base_socket);
        }

        // The `SIO_BASE_HANDLE` should not be intercepted by LSPs, therefore
        // it should not fail as long as `raw_socket` is a valid socket. See
        // https://docs.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls.
        // However, at least one known LSP deliberately breaks it, so we try
        // some alternative IOCTLs, starting with the most appropriate one.
        for &ioctl in &[
            SIO_BSP_HANDLE_SELECT,
            SIO_BSP_HANDLE_POLL,
            SIO_BSP_HANDLE,
        ] {
            if let Ok(base_socket) = try_get_base_socket(raw_socket, ioctl) {
                // Since we know now that we're dealing with an LSP (otherwise
                // SIO_BASE_HANDLE would't have failed), only return any result
                // when it is different from the original `raw_socket`.
                if base_socket != raw_socket {
                    return Ok(base_socket);
                }
            }
        }

        // If the alternative IOCTLs also failed, return the original error.
        let os_error = res.unwrap_err();
        let err = io::Error::from_raw_os_error(os_error);
        Err(err)
    }
}

impl Drop for SelectorInner {
    fn drop(&mut self) {
        loop {
            let events_num: usize;
            let mut statuses: [CompletionStatus; 1024] = [CompletionStatus::zero(); 1024];

            let result = self
                .cp
                .get_many(&mut statuses, Some(std::time::Duration::from_millis(0)));
            match result {
                Ok(iocp_events) => {
                    events_num = iocp_events.iter().len();
                    for iocp_event in iocp_events.iter() {
                        if iocp_event.overlapped().is_null() {
                            // Custom event
                        } else if iocp_event.token() % 2 == 1 {
                            // Named pipe, dispatch the event so it can release resources
                            let callback = unsafe {
                                (*(iocp_event.overlapped() as *mut super::Overlapped)).callback
                            };

                            callback(iocp_event.entry(), None);
                        } else {
                            // drain sock state to release memory of Arc reference
                            let _sock_state = from_overlapped(iocp_event.overlapped());
                        }
                    }
                }

                Err(_) => {
                    break;
                }
            }

            if events_num == 0 {
                // continue looping until all completion statuses have been drained
                break;
            }
        }
    }
}

cfg_net! {
    fn interests_to_flags(interests: Interest) -> u32 {
        let mut flags = 0;

        if interests.is_readable() {
            flags |= POLL_RECEIVE | POLL_ACCEPT | POLL_DISCONNECT;
        }

        if interests.is_writable() {
            flags |= POLL_SEND;
        }

        flags
    }
}


pub const POLL_RECEIVE: u32 = 0b0_0000_0001;
pub const POLL_SEND: u32 = 0b0_0000_0100;
pub const POLL_DISCONNECT: u32 = 0b0_0000_1000;
pub const POLL_ABORT: u32 = 0b0_0001_0000;
// Not used as it indicated in each event where a connection is connected, not
// just the first time a connection is established.
// Also see https://github.com/piscisaureus/wepoll/commit/8b7b340610f88af3d83f40fb728e7b850b090ece.
pub const POLL_ACCEPT: u32 = 0b0_1000_0000;
pub const POLL_CONNECT_FAIL: u32 = 0b1_0000_0000;
