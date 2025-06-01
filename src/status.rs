use std::time::{Instant};
use sysinfo::{Disks, System};
use serde_json::{json, Value};




fn get_uptime(start: Instant) -> u64 {
    Instant::now().duration_since(start).as_secs()
}


fn get_cpu_usage(sys: &mut System) -> u64 {
    sys.refresh_all();
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    sys.refresh_all();
    let cpus = sys.cpus();
    let total_usage: f32 = cpus.iter()
        .map(|cpu| cpu.cpu_usage())
        .sum();

    let avg_usage = total_usage / cpus.len() as f32;
    avg_usage.round() as u64
}


fn get_ram(sys: &mut System) -> u64{
    sys.refresh_all();
    let total = sys.total_memory() / 1000000; //mb
    let used = sys.used_memory() / 1000000; //mb
    used / (total / 100) // %                         
}


fn get_disks() -> u64 {
    let disks = Disks::new_with_refreshed_list();
    let mut total_used = 0.0;
    let mut total_space = 0.0;

    for disk in &disks {
        total_space += disk.total_space() as f64;
        total_used += (disk.total_space() - disk.available_space()) as f64;
    }

    let usage_percent = if total_space > 0.0 {
        (total_used / total_space) * 100.0
    } else {
        0.0
    };
    usage_percent.round() as u64
}



pub fn get_status(start: Instant) -> Value {
    let mut sys = System::new();
    let uptime = get_uptime(start);
    let cpu_usage: u64 = get_cpu_usage(&mut sys);
    let ram_usage: u64 = get_ram(&mut sys);
    let disk_usage = get_disks();

    json!({
        "uptime": uptime,
        "cpu": cpu_usage,
        "ram": ram_usage,
        "disk": disk_usage
    })
}

