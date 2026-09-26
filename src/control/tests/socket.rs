use super::{StartupLock, remove_stale_socket};
use std::{
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    sync::mpsc,
    thread,
    time::Duration,
};

#[test]
fn serializes_stale_socket_cleanup_through_listener_bind() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("control directory should be private");
    let uid = std::fs::metadata(directory.path())
        .expect("control directory metadata should be readable")
        .uid();
    let socket = directory.path().join("control.sock");

    drop(UnixListener::bind(&socket).expect("stale test socket should bind"));
    let first_lock = StartupLock::acquire(&socket, uid).expect("first startup should lock");
    assert!(
        remove_stale_socket(&socket, uid).expect("stale socket should be removed"),
        "the first startup should remove the disconnected socket"
    );
    let listener = UnixListener::bind(&socket).expect("first startup should bind listener");

    let socket_for_second = socket.clone();
    let (started_sender, started_receiver) = mpsc::channel();
    let (finished_sender, finished_receiver) = mpsc::channel();
    let second_start = thread::spawn(move || {
        started_sender
            .send(())
            .expect("test should observe the second start");
        let _lock = StartupLock::acquire(&socket_for_second, uid)
            .expect("second startup should acquire the lock after the first binds");
        let removed = remove_stale_socket(&socket_for_second, uid)
            .expect("active socket check should succeed");
        let bind_failed = UnixListener::bind(&socket_for_second).is_err();
        finished_sender
            .send((removed, bind_failed))
            .expect("test should observe the second start result");
    });

    started_receiver
        .recv()
        .expect("second startup should reach the lock");
    assert!(
        finished_receiver
            .recv_timeout(Duration::from_millis(50))
            .is_err(),
        "second startup must wait while the first holds the lock through bind"
    );
    drop(first_lock);

    assert_eq!(
        finished_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("second startup should continue after the first binds"),
        (false, true),
        "second startup must preserve the active socket and fail to bind"
    );
    second_start
        .join()
        .expect("second startup thread should finish");
    assert!(
        UnixStream::connect(&socket).is_ok(),
        "first startup's listener should remain reachable"
    );
    drop(listener);
}
