use std::process::{Child, Command};
use std::time::Duration;

pub(super) struct Process(Child);

impl Process {
    pub(super) fn spawn(command: &mut Command) -> Self {
        Self(command.spawn().expect("start qualification subprocess"))
    }

    pub(super) fn assert_running(&mut self) {
        assert!(
            self.0.try_wait().unwrap().is_none(),
            "subprocess exited early"
        );
    }

    pub(super) async fn finish(&mut self, seconds: u64) {
        tokio::time::timeout(Duration::from_secs(seconds), async {
            loop {
                if let Some(status) = self.0.try_wait().unwrap() {
                    assert!(status.success(), "subprocess failed: {status}");
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("qualification subprocess deadline");
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn failed_commands_are_not_accepted() {
    let task = tokio::spawn(async {
        Process::spawn(Command::new("sh").args(["-c", "exit 1"]))
            .finish(1)
            .await;
    });
    assert!(task.await.unwrap_err().is_panic());
}

#[tokio::test]
async fn subprocess_wait_does_not_block_async_executor() {
    let mut process = Process::spawn(Command::new("sleep").arg("10"));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), process.finish(1))
            .await
            .is_err()
    );
}
