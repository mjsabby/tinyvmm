//! The guest's display as it was last flushed, in BGRA, shared by the
//! virtio-gpu device with the window and the recorder that show it. A flush
//! draws the new picture on the vCPU thread that ran it, in a spare buffer no
//! reader is using (copying in only what changed), and publishes it; the window
//! and the recorder take the latest picture by reference and read it on their
//! own threads, so neither a paint nor an encode holds up the guest.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// Flushes whose damage is remembered, for bringing a spare up to date.
const RECENT: usize = 4;
/// Pictures kept besides the latest, for later flushes to draw on.
const SPARES: usize = 2;

/// A rectangle of the scanout, in pixels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Area {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl Area {
    pub fn full(width: u32, height: u32) -> Area {
        Area {
            x: 0,
            y: 0,
            width,
            height,
        }
    }

    /// The smallest area holding both.
    pub fn union(self, other: Area) -> Area {
        let x = self.x.min(other.x);
        let y = self.y.min(other.y);
        Area {
            x,
            y,
            width: (self.x + self.width).max(other.x + other.width) - x,
            height: (self.y + self.height).max(other.y + other.height) - y,
        }
    }
}

/// A picture of the scanout.
#[derive(Default)]
pub struct Frame {
    /// Top-down BGRA, `width * 4` bytes per row.
    pub buf: Vec<u8>,
    pub width: u32,
    pub height: u32,
    /// The flush that drew it, counting from 1; 0 for a blank buffer.
    seq: u64,
}

impl Frame {
    /// Which flush drew this picture; later flushes have higher numbers.
    pub fn seq(&self) -> u64 {
        self.seq
    }
}

#[derive(Default)]
pub struct Scanout {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// The latest picture.
    front: Option<Arc<Frame>>,
    /// Older pictures, for flushes to draw on once no reader holds them.
    spares: Vec<Arc<Frame>>,
    /// The latest flushes' damage, oldest first, by flush number.
    recent: VecDeque<(u64, Area)>,
    /// What changed since the window last looked.
    window_dirty: Option<Area>,
}

impl State {
    /// The bounding box of what the flushes after `seq` changed, or `None` if
    /// some of them are forgotten.
    fn changed_since(&self, seq: u64) -> Option<Area> {
        let &(first, _) = self.recent.front()?;
        if seq == 0 || seq + 1 < first {
            return None;
        }
        self.recent
            .iter()
            .filter(|&&(n, _)| n > seq)
            .map(|&(_, a)| a)
            .reduce(Area::union)
    }
}

impl Scanout {
    /// Take a flush of a `width`x`height` scanout that changed `damage`:
    /// `fill(buf, area)` must draw `area` of the picture into `buf`, a whole
    /// frame that already shows the rest of it. `area` is `damage`, or the
    /// whole frame when the size changed.
    pub fn flush(&self, width: u32, height: u32, damage: Area, fill: impl FnOnce(&mut [u8], Area)) {
        let mut s = self.state.lock().unwrap();
        let full = Area::full(width, height);
        // Draw on the newest spare no reader holds (readers only get `front`,
        // so none can take it meanwhile), else on a new buffer.
        let free = s
            .spares
            .iter_mut()
            .enumerate()
            .filter_map(|(i, f)| Arc::get_mut(f).map(|f| (f.seq, i)))
            .max()
            .map(|(_, i)| i);
        let mut back = free.map_or_else(Arc::default, |i| s.spares.swap_remove(i));
        let frame = Arc::get_mut(&mut back).expect("a spare no reader holds");
        if (frame.width, frame.height) != (width, height) {
            frame.width = width;
            frame.height = height;
            frame.seq = 0;
            frame.buf.clear();
            frame.buf.resize(width as usize * height as usize * 4, 0);
        }
        let area = match &s.front {
            Some(f) if (f.width, f.height) == (width, height) => {
                if damage != full {
                    // Catch up with the latest picture, outside `damage` too.
                    let stale = s.changed_since(frame.seq).unwrap_or(full);
                    copy_area(&f.buf, &mut frame.buf, width, stale);
                }
                damage
            }
            _ => full,
        };
        fill(&mut frame.buf, area);
        let seq = s.front.as_ref().map_or(0, |f| f.seq) + 1;
        frame.seq = seq;
        if area == full {
            // Everything changed, so earlier damage (perhaps at another size)
            // no longer matters: older spares get redrawn whole.
            s.recent.clear();
            s.window_dirty = None;
        }
        s.recent.push_back((seq, area));
        if s.recent.len() > RECENT {
            s.recent.pop_front();
        }
        s.window_dirty = Some(s.window_dirty.map_or(area, |d| d.union(area)));
        if let Some(old) = s.front.replace(back) {
            s.spares.push(old);
            if s.spares.len() > SPARES {
                let oldest = (0..s.spares.len())
                    .min_by_key(|&i| s.spares[i].seq)
                    .unwrap();
                s.spares.swap_remove(oldest);
            }
        }
    }

    /// The latest picture, if there has been a flush.
    pub fn latest(&self) -> Option<Arc<Frame>> {
        self.state.lock().unwrap().front.clone()
    }

    /// The latest picture, if a flush came after the one numbered `seq`.
    pub fn newer_than(&self, seq: u64) -> Option<Arc<Frame>> {
        let s = self.state.lock().unwrap();
        s.front.as_ref().filter(|f| f.seq > seq).cloned()
    }

    /// For the window, which shows a picture of `size` pixels: what changed
    /// since the last call, or all of it when the size changed (updating
    /// `size`); `None` if nothing did.
    pub fn window_update(&self, size: &mut (u32, u32)) -> Option<Area> {
        let mut s = self.state.lock().unwrap();
        let dirty = s.window_dirty.take()?;
        let f = s.front.as_ref()?;
        if *size == (f.width, f.height) {
            return Some(dirty);
        }
        *size = (f.width, f.height);
        Some(Area::full(f.width, f.height))
    }
}

/// Copy `area` from `src` to `dst`, frames `width` pixels wide.
fn copy_area(src: &[u8], dst: &mut [u8], width: u32, area: Area) {
    let stride = width as usize * 4;
    let row = area.width as usize * 4;
    let first = area.y as usize * stride + area.x as usize * 4;
    if row == stride {
        let len = row * area.height as usize;
        dst[first..first + len].copy_from_slice(&src[first..first + len]);
        return;
    }
    for i in 0..area.height as usize {
        let at = first + i * stride;
        dst[at..at + row].copy_from_slice(&src[at..at + row]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fill `area` of a frame `width` pixels wide with pixels whose blue byte
    /// is `v`.
    fn paint(v: u8, width: u32) -> impl FnOnce(&mut [u8], Area) {
        move |buf, area| {
            for y in area.y..area.y + area.height {
                for x in area.x..area.x + area.width {
                    let at = (y * width + x) as usize * 4;
                    buf[at..at + 4].copy_from_slice(&[v, 0, 0, 0]);
                }
            }
        }
    }

    fn blues(frame: &[u8]) -> Vec<u8> {
        frame.as_chunks::<4>().0.iter().map(|px| px[0]).collect()
    }

    /// The window hears of what changed (the union, when it falls behind;
    /// everything, on a new size); the recorder sees each picture once.
    #[test]
    fn readers_follow_partial_flushes_and_resizes() {
        let s = Scanout::default();
        let mut size = (0, 0);
        assert!(s.latest().is_none());
        assert_eq!(s.window_update(&mut size), None);
        s.flush(4, 3, Area::full(4, 3), paint(1, 4));
        assert_eq!(s.window_update(&mut size), Some(Area::full(4, 3)));
        assert_eq!(
            (size, blues(&s.latest().unwrap().buf)),
            ((4, 3), vec![1; 12])
        );

        // Two flushes before the window looks: it repaints their bounding box.
        let a = Area {
            x: 0,
            y: 0,
            width: 1,
            height: 1,
        };
        let b = Area {
            x: 2,
            y: 1,
            width: 1,
            height: 1,
        };
        s.flush(4, 3, a, paint(2, 4));
        s.flush(4, 3, b, paint(3, 4));
        let union = Area {
            x: 0,
            y: 0,
            width: 3,
            height: 2,
        };
        assert_eq!(s.window_update(&mut size), Some(union));
        assert_eq!(
            blues(&s.latest().unwrap().buf),
            [2, 1, 1, 1, 1, 1, 3, 1, 1, 1, 1, 1]
        );
        assert_eq!(s.window_update(&mut size), None);

        let seen = s.newer_than(0).unwrap().seq();
        assert!(s.newer_than(seen).is_none());

        // A new size (here, with as many pixels) redraws the whole frame,
        // whatever the damage says.
        s.flush(3, 4, a, paint(4, 3));
        assert_eq!(s.window_update(&mut size), Some(Area::full(3, 4)));
        assert_eq!(size, (3, 4));
        let f = s.newer_than(seen).unwrap();
        assert_eq!((f.width, f.height, blues(&f.buf)), (3, 4, vec![4; 12]));
    }

    /// A spare left from before a mode change is redrawn whole, not caught up
    /// with damage from pictures of another size.
    #[test]
    fn spares_from_before_a_size_change_are_redrawn_whole() {
        let s = Scanout::default();
        let dot = Area {
            x: 0,
            y: 0,
            width: 1,
            height: 1,
        };
        // Three 4x3 buffers: two readers force the third.
        s.flush(4, 3, Area::full(4, 3), paint(1, 4));
        let r1 = s.latest();
        s.flush(4, 3, dot, paint(2, 4));
        let r2 = s.latest();
        s.flush(4, 3, dot, paint(3, 4));
        drop((r1, r2));
        // To 3x4 and back, with a reader holding the 3x4 picture, so the next
        // flush draws on the oldest 4x3 buffer.
        s.flush(3, 4, Area::full(3, 4), paint(4, 3));
        let r3 = s.latest();
        s.flush(4, 3, Area::full(4, 3), paint(5, 4));
        s.flush(4, 3, dot, paint(6, 4));
        let mut want = vec![5; 12];
        want[0] = 6;
        assert_eq!(blues(&s.latest().unwrap().buf), want);
        drop(r3);
    }

    /// Whichever buffer a flush draws on, and however stale it was, the
    /// picture it publishes is the whole frame as flushed so far, across mode
    /// changes too; a picture a reader holds never changes, and the spares
    /// stay bounded.
    #[test]
    fn pictures_stay_whole_while_readers_hold_them() {
        let sizes = [(8u32, 6u32), (6, 8)];
        let (mut w, mut h) = sizes[0];
        let s = Scanout::default();
        s.flush(w, h, Area::full(w, h), paint(0, w));
        let mut model = vec![0u8; (w * h) as usize];
        let mut held: Vec<(Arc<Frame>, Vec<u8>)> = Vec::new();
        let mut rng = 0x1234_5678u32;
        let mut next = |n: u32| {
            rng = rng.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (rng >> 8) % n
        };
        for v in 1..=600u32 {
            if next(16) == 0 {
                // A mode change: the whole frame is new.
                (w, h) = sizes[(w == sizes[0].0) as usize];
                s.flush(w, h, Area::full(w, h), paint(v as u8, w));
                model = vec![v as u8; (w * h) as usize];
            } else {
                let (x, y) = (next(w), next(h));
                let area = Area {
                    x,
                    y,
                    width: 1 + next(w - x),
                    height: 1 + next(h - y),
                };
                s.flush(w, h, area, paint(v as u8, w));
                for yy in y..y + area.height {
                    for xx in x..x + area.width {
                        model[(yy * w + xx) as usize] = v as u8;
                    }
                }
            }
            assert_eq!(blues(&s.latest().unwrap().buf), model, "flush {v}");
            // Readers come and go, some holding a picture over many flushes.
            match next(4) {
                0 if held.len() < 3 => {
                    let f = s.latest().unwrap();
                    let b = blues(&f.buf);
                    held.push((f, b));
                }
                1 if !held.is_empty() => drop(held.remove(0)),
                _ => {}
            }
            for (f, b) in &held {
                assert_eq!(&blues(&f.buf), b);
            }
            assert!(s.state.lock().unwrap().spares.len() <= SPARES);
        }
    }
}
