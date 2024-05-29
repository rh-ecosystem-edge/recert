#[derive(Clone)]
pub(crate) struct RunTime {
    start: std::time::Instant,
    end: std::time::Instant,
}

impl RunTime {
    pub(crate) fn since_start(start: std::time::Instant) -> Self {
        Self {
            start,
            end: std::time::Instant::now(),
        }
    }
}

impl serde::Serialize for RunTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let duration = self.end - self.start;
        serializer.serialize_str(&format!("{}.{:03}s", duration.as_secs(), duration.subsec_millis()))
    }
}

#[derive(serde::Serialize, Clone)]
pub(crate) struct RunTimes {
    pub(crate) scan_run_time: RunTime,
    pub(crate) rsa_run_time: RunTime,
    pub(crate) processing_run_time: RunTime,
    pub(crate) commit_to_etcd_and_disk_run_time: RunTime,
    pub(crate) ocp_postprocessing_run_time: RunTime,
    pub(crate) commit_to_actual_etcd_run_time: RunTime,
}

pub(crate) struct RecertifyTiming {
    pub(crate) scan_run_time: RunTime,
    pub(crate) rsa_run_time: RunTime,
    pub(crate) processing_run_time: RunTime,
}

impl RecertifyTiming {
    pub(crate) fn immediate() -> Self {
        Self {
            scan_run_time: RunTime::since_start(std::time::Instant::now()),
            rsa_run_time: RunTime::since_start(std::time::Instant::now()),
            processing_run_time: RunTime::since_start(std::time::Instant::now()),
        }
    }
}

pub(crate) struct FinalizeTiming {
    pub(crate) commit_to_etcd_and_disk_run_time: RunTime,
    pub(crate) ocp_postprocessing_run_time: RunTime,
    pub(crate) commit_to_actual_etcd_run_time: RunTime,
}

pub(crate) fn combine_timings(recertify_timing: RecertifyTiming, finalize_timing: FinalizeTiming) -> RunTimes {
    RunTimes {
        scan_run_time: recertify_timing.scan_run_time,
        rsa_run_time: recertify_timing.rsa_run_time,
        processing_run_time: recertify_timing.processing_run_time,
        commit_to_etcd_and_disk_run_time: finalize_timing.commit_to_etcd_and_disk_run_time,
        ocp_postprocessing_run_time: finalize_timing.ocp_postprocessing_run_time,
        commit_to_actual_etcd_run_time: finalize_timing.commit_to_actual_etcd_run_time,
    }
}
