import { useCallback, useEffect, useState, type FormEvent } from 'react';

type User = { id: number; name: string; admin: boolean };
type Room = { id: number; name: string };
type Booking = { id: number; roomId: number; userId: number; userName: string; start: string; end: string };

async function api<T = unknown>(method: string, path: string, body?: object): Promise<T> {
  const res = await fetch(`/api${path}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body && JSON.stringify(body),
  });
  const data = await res.json();
  // Expired Microsoft session: re-check roles silently. The server already dropped the session, so this cannot loop.
  if (res.status === 401 && data.reauth) {
    location.assign('/api/login?silent=1');
    return new Promise<T>(() => {}); // keep the current screen while the browser navigates away
  }
  if (!res.ok) throw new Error(data.error ?? res.statusText);
  return data;
}

const today = () => new Date().toLocaleDateString('sv'); // sv locale formats as YYYY-MM-DD
const hhmm = (iso: string) => new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

export function App() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [loginError] = useState(() => new URLSearchParams(location.search).has('login_error'));

  useEffect(() => {
    if (loginError) history.replaceState(null, '', location.pathname);
    api<User>('GET', '/me').then(setUser, () => {}).finally(() => setLoading(false));
  }, [loginError]);

  const logout = async () => {
    await api('POST', '/logout').catch(() => {});
    setUser(null);
  };

  if (loading) return null;
  if (!user) return <Login error={loginError ? 'Sign-in failed, try again' : ''} />;
  return (
    <>
      <header>
        <h1>Desk Booking</h1>
        <span>
          {user.name} {user.admin && <span className="badge">admin</span>} <button type="button" onClick={logout}>Log out</button>
        </span>
      </header>
      <Booker user={user} />
    </>
  );
}

function Login({ error }: { error: string }) {
  return (
    <div className="login card">
      <h1>Desk Booking</h1>
      <a className="button" href="/api/login">Sign in with Microsoft</a>
      {error && <p className="error" role="alert">{error}</p>}
    </div>
  );
}

function Booker({ user }: { user: User }) {
  const [rooms, setRooms] = useState<Room[]>([]);
  const [bookings, setBookings] = useState<Booking[]>([]);
  const [mine, setMine] = useState<Booking[]>([]);
  const [date, setDate] = useState(today);
  const [roomId, setRoomId] = useState('');
  const [start, setStart] = useState('09:00');
  const [end, setEnd] = useState('17:00');
  const [error, setError] = useState('');
  const [tab, setTab] = useState<'book' | 'mine' | 'rooms'>('book');

  const load = useCallback(async () => {
    const from = new Date(`${date}T00:00`);
    const to = new Date(from);
    to.setDate(to.getDate() + 1);
    const [r, b, m] = await Promise.all([
      api<Room[]>('GET', '/rooms'),
      api<Booking[]>('GET', `/bookings?from=${from.toISOString()}&to=${to.toISOString()}`),
      api<Booking[]>('GET', '/bookings/mine'),
    ]);
    setRooms(r);
    setBookings(b);
    setMine(m);
  }, [date]);

  useEffect(() => { load().catch((e) => setError(e.message)); }, [load]);

  // Runs an action, shows its error if any, then refreshes the view.
  const act = (fn: () => Promise<unknown>) => async () => {
    setError('');
    try {
      await fn();
      await load();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const book = (e: FormEvent) => {
    e.preventDefault();
    act(() => api('POST', '/bookings', {
      roomId: Number(roomId || rooms[0]?.id),
      start: new Date(`${date}T${start}`).toISOString(),
      end: new Date(`${date}T${end}`).toISOString(),
    }))();
  };

  const tabs = ([['book', 'Bookings'], ['mine', 'My bookings'], ['rooms', 'Manage rooms']] as const).filter(([id]) => id !== 'rooms' || user.admin);

  return (
    <>
      <div className="tabs" role="tablist">
        {tabs.map(([id, label]) => (
          <button type="button" key={id} role="tab" aria-selected={tab === id} onClick={() => { setTab(id); setError(''); }}>
            {label}
          </button>
        ))}
      </div>
      {error && <p className="error" role="alert">{error}</p>}
      {tab === 'rooms' && <RoomAdmin rooms={rooms} act={act} />}
      {tab === 'mine' && <MyBookings bookings={mine} rooms={rooms} act={act} />}
      {tab === 'book' && <>
      <form onSubmit={book}>
        <label>Date<input type="date" value={date} onChange={(e) => setDate(e.target.value)} required /></label>
        <label>Room
          <select value={roomId} onChange={(e) => setRoomId(e.target.value)} required>
            {rooms.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
          </select>
        </label>
        <label>From<input type="time" value={start} onChange={(e) => setStart(e.target.value)} required /></label>
        <label>To<input type="time" value={end} onChange={(e) => setEnd(e.target.value)} required /></label>
        <button type="submit" disabled={!rooms.length}>Book</button>
      </form>
      {!rooms.length && <p className="muted">No rooms yet.{user.admin && ' Add one in Manage rooms.'}</p>}

      <div className="rooms">
      {rooms.map((r) => {
        const list = bookings.filter((b) => b.roomId === r.id);
        return (
          <section key={r.id} aria-label={r.name}>
            <h3>{r.name}</h3>
            {!list.length && <p className="muted">Free all day</p>}
            <ul>
              {list.map((b) => (
                <li key={b.id}>
                  <span className="time">{hhmm(b.start)}–{hhmm(b.end)}</span> {b.userName}
                  {(b.userId === user.id || user.admin) && (
                    <button type="button" className="danger" onClick={act(() => api('DELETE', `/bookings/${b.id}`))}>Cancel</button>
                  )}
                </li>
              ))}
            </ul>
          </section>
        );
      })}
      </div>
      </>}
    </>
  );
}

function MyBookings({ bookings, rooms, act }: { bookings: Booking[]; rooms: Room[]; act: (fn: () => Promise<unknown>) => () => Promise<void> }) {
  return (
    <section>
      <h2>My bookings</h2>
      {!bookings.length && <p className="muted">You have no upcoming bookings.</p>}
      <ul>
        {bookings.map((b) => (
          <li key={b.id}>
            {new Date(b.start).toLocaleDateString([], { weekday: 'short', day: 'numeric', month: 'short' })}{' '}
            <span className="time">{hhmm(b.start)}–{hhmm(b.end)}</span> {rooms.find((r) => r.id === b.roomId)?.name}
            <button type="button" className="danger" onClick={act(() => api('DELETE', `/bookings/${b.id}`))}>Cancel</button>
          </li>
        ))}
      </ul>
    </section>
  );
}

function RoomAdmin({ rooms, act }: { rooms: Room[]; act: (fn: () => Promise<unknown>) => () => Promise<void> }) {
  const [name, setName] = useState('');

  const rename = (r: Room) => {
    const next = prompt('New name', r.name);
    if (next) act(() => api('PATCH', `/rooms/${r.id}`, { name: next }))();
  };
  const remove = (r: Room) => {
    if (confirm(`Delete ${r.name}? All its bookings are deleted too.`)) act(() => api('DELETE', `/rooms/${r.id}`))();
  };

  return (
    <section>
      <h2>Manage rooms</h2>
      <form onSubmit={(e) => { e.preventDefault(); act(() => api('POST', '/rooms', { name }).then(() => setName('')))(); }}>
        <label>New room or desk<input value={name} onChange={(e) => setName(e.target.value)} required maxLength={50} /></label>
        <button type="submit">Add</button>
      </form>
      <ul>
        {rooms.map((r) => (
          <li key={r.id}>
            {r.name}
            <button type="button" onClick={() => rename(r)}>Rename</button>
            <button type="button" className="danger" onClick={() => remove(r)}>Delete</button>
          </li>
        ))}
      </ul>
    </section>
  );
}
