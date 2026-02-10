use std::process::Command;

fn main() {
    // Execute the 'date' command to get your specific format
    let output = Command::new("date")
        .arg("+%Y%m%d.%H%M%S")
        .output()
        .expect("failed to execute date");

    let build_time = String::from_utf8_lossy(&output.stdout).trim().to_string();

    // Pass this value to the compiler as an environment variable
    println!("cargo:rustc-env=BUILD_VERSION={}", build_time);
}
