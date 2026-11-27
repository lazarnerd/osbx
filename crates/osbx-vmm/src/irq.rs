//! Interrupt lines devices raise, independent of how the hypervisor backend delivers them
//! (an irqfd into KVM's in-kernel IOAPIC, or osbx's own IOAPIC on Windows).

use std::sync::Arc;

/// One edge-triggered interrupt line.
pub trait IrqLine: Send + Sync {
    /// Pulse the line once.
    fn pulse(&self);
}

/// A shared interrupt line.
pub type Irq = Arc<dyn IrqLine>;
