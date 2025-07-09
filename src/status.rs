// Use's

use std::time::Instant;
use sysinfo::{Disks, System};
use serde_json::{json, Value};
use tracing::{info, warn};



fn get_uptime(start: Instant) -> u64 {
    let uptime = Instant::now().duration_since(start).as_secs();
    info!(target: "status", "Uptime calculated: {} seconds", uptime);
    uptime
}


fn get_cpu_usage(sys: &mut System) -> u64 {
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    sys.refresh_cpu_all();

    let cpus = sys.cpus();
    if cpus.is_empty() {
        warn!(target: "status", "No CPU information available");
        return 0;
    }

    let total_usage: f32 = cpus.iter().map(|cpu| cpu.cpu_usage()).sum();
    let avg_usage = total_usage / cpus.len() as f32;
    let cpu_usage_rounded = avg_usage.round() as u64;

    info!(target: "status", "CPU average usage: {:.2}%, rounded: {}", avg_usage, cpu_usage_rounded);

    cpu_usage_rounded
}


fn get_ram(sys: &mut System) -> u64 {
    sys.refresh_memory();
    let total = sys.total_memory();
    let used = sys.used_memory();

    if total == 0 {
        warn!(target: "status", "Total RAM reported as zero");
        return 0;
    }

    let ram_percent = ((used as f64 / total as f64) * 100.0).round() as u64;

    info!(target: "status", "RAM usage: {} / {} ({}%)", used, total, ram_percent);

    ram_percent
}


fn get_disks_usage() -> u64 {
    let mut disks = Disks::new_with_refreshed_list();
    let mut total_used = 0.0;
    let mut total_space = 0.0;

    for disk in &mut disks {
        disk.refresh();
        let disk_total = disk.total_space() as f64;
        let disk_used = (disk.total_space() - disk.available_space()) as f64;

        total_space += disk_total;
        total_used += disk_used;

        info!(
            target: "status",
            "Disk {}: total {} bytes, used {} bytes",
            disk.name().to_string_lossy(),
            disk_total,
            disk_used
        );
    }

    if total_space == 0.0 {
        warn!(target: "status", "No disk space information available");
        return 0;
    }

    let disk_percent = ((total_used / total_space) * 100.0).round() as u64;

    info!(
        target: "status",
        "Total disk usage: {} / {} bytes ({}%)",
        total_used, total_space, disk_percent
    );

    disk_percent
}


pub fn get_status(start: Instant) -> Value {
    let mut sys = System::new();

    let status = json!({
        "uptime": get_uptime(start),
        "cpu": get_cpu_usage(&mut sys),
        "ram": get_ram(&mut sys),
        "disk": get_disks_usage()
    });

    info!(target: "status", "Status collected: {}", status);

    status
}

// TODO: Fix cpu load checker