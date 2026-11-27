//! `osbx-probe [--run-guest] [--require-nested]`: the `kvm@1` probe as a small static binary,
//! shipped inside guests to check that a sandbox can itself run KVM.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let ok = osbx_vmm::report_probe(
        args.iter().any(|a| a == "--run-guest"),
        args.iter().any(|a| a == "--require-nested"),
    );
    std::process::exit(if ok { 0 } else { 1 });
}
