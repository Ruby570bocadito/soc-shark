//! Ring buffer lock-free SPSC (single-producer / single-consumer).
//!
//! Es la cola que en la fase 2 separará el **Ingestor** (productor, hilo de
//! captura) del pool de **Dissectors** (consumidores), cumpliendo la
//! propiedad del diseño: el productor nunca se bloquea — si el buffer se
//! llena, `push` devuelve `Err` y la política de drop la decide el caller
//! (la captura no debe perder el hilo del kernel por un consumidor lento).
//!
//! Restricciones (deliberadas y documentadas):
//! - Capacidad potencia de dos (indexado con máscara).
//! - Un solo productor y un solo consumidor. Para MPMC se usará crossbeam
//!   en la fase 2, o este mismo tipo por cada par de etapas del pipeline.
//! - Ordenamiento `SeqCst` (correcto por diseño; optimizable a AcqRel con
//!   benchmarks en fase 2).

use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Cola circular lock-free de un productor y un consumidor.
pub struct SpscRing<T> {
    buf: UnsafeCell<Vec<MaybeUninit<T>>>,
    mask: usize,
    head: AtomicUsize, // índice de escritura (productor)
    tail: AtomicUsize, // índice de lectura (consumidor)
}

// SPSC: T se transfiere de productor a consumidor (ambos hilos pueden
// poseerlo momentáneamente) → Send+Sync si T: Send.
unsafe impl<T: Send> Send for SpscRing<T> {}
unsafe impl<T: Send> Sync for SpscRing<T> {}

impl<T> SpscRing<T> {
    /// Crea la cola; `cap_pow2` debe ser potencia de dos (>= 1).
    pub fn new(cap_pow2: usize) -> Self {
        assert!(
            cap_pow2.is_power_of_two(),
            "la capacidad debe ser potencia de dos"
        );
        let mut v = Vec::with_capacity(cap_pow2);
        v.resize_with(cap_pow2, MaybeUninit::uninit);
        SpscRing {
            buf: UnsafeCell::new(v),
            mask: cap_pow2 - 1,
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    pub fn capacity(&self) -> usize {
        self.mask + 1
    }

    /// Elementos actualmente en la cola.
    pub fn len(&self) -> usize {
        let h = self.head.load(Ordering::SeqCst);
        let t = self.tail.load(Ordering::SeqCst);
        h.wrapping_sub(t)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Inserta sin bloquear. `Err(v)` si está llena (política sin drop).
    pub fn push(&self, v: T) -> Result<(), T> {
        let h = self.head.load(Ordering::SeqCst);
        if h.wrapping_sub(self.tail.load(Ordering::SeqCst)) > self.mask {
            return Err(v);
        }
        unsafe {
            let vec: &mut Vec<MaybeUninit<T>> = &mut *self.buf.get();
            vec[h & self.mask].write(v);
        }
        self.head.store(h.wrapping_add(1), Ordering::SeqCst);
        Ok(())
    }

    /// Extrae el elemento más antiguo, si lo hay.
    pub fn pop(&self) -> Option<T> {
        let t = self.tail.load(Ordering::SeqCst);
        if t == self.head.load(Ordering::SeqCst) {
            return None;
        }
        let v = unsafe {
            let vec: &mut Vec<MaybeUninit<T>> = &mut *self.buf.get();
            vec[t & self.mask].as_ptr().read()
        };
        self.tail.store(t.wrapping_add(1), Ordering::SeqCst);
        Some(v)
    }
}

impl<T> Drop for SpscRing<T> {
    fn drop(&mut self) {
        // Drena los elementos pendientes para liberarlos correctamente.
        while self.pop().is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn fifo_basico() {
        let q: SpscRing<u32> = SpscRing::new(4);
        assert!(q.is_empty());
        for i in 0..4u32 {
            assert!(q.push(i).is_ok());
        }
        assert_eq!(q.len(), 4);
        // Llena: rechaza sin bloquear.
        assert!(q.push(99).is_err());
        for i in 0..4u32 {
            assert_eq!(q.pop(), Some(i));
        }
        assert!(q.pop().is_none());
    }

    #[test]
    fn wrapping_de_indices() {
        let q: SpscRing<usize> = SpscRing::new(2);
        for i in 0..1000usize {
            q.push(i).unwrap();
            assert_eq!(q.pop(), Some(i));
        }
    }

    #[test]
    fn productor_y_consumidor_en_hilos() {
        const N: usize = 100_000;
        let q: Arc<SpscRing<usize>> = Arc::new(SpscRing::new(1024));
        let prod = Arc::clone(&q);
        let cons = Arc::clone(&q);
        let t = thread::spawn(move || {
            for i in 0..N {
                while prod.push(i).is_err() {
                    std::hint::spin_loop();
                }
            }
        });
        let mut sum = 0u64;
        let mut got = 0usize;
        while got < N {
            if let Some(v) = cons.pop() {
                sum += v as u64;
                got += 1;
            } else {
                std::hint::spin_loop();
            }
        }
        t.join().unwrap();
        assert_eq!(sum, (N * (N - 1) / 2) as u64);
    }

    #[test]
    #[should_panic(expected = "potencia de dos")]
    fn rechaza_capacidad_invalida() {
        let _: SpscRing<u8> = SpscRing::new(3);
    }
}
