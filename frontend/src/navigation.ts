import { useCallback, useEffect, useRef, useState } from 'react';
import { useDraftGuard } from './ui';
export type View =
  | 'overview'
  | 'credentials'
  | 'servers'
  | 'approvals'
  | 'users'
  | 'groups'
  | 'roles'
  | 'clients'
  | 'audit';
export interface Route {
  view: View;
  item?: string;
  tab?: string;
}
const views: View[] = [
  'overview',
  'credentials',
  'servers',
  'approvals',
  'users',
  'groups',
  'roles',
  'clients',
  'audit',
];
export function href(route: Route) {
  return (
    '#' +
    [route.view, route.item, route.tab]
      .filter((v) => v !== undefined)
      .map((v) => encodeURIComponent(v!))
      .join('/')
  );
}
function read(): Route {
  try {
    const [view, item, tab] = location.hash.slice(1).split('/').map(decodeURIComponent);
    return { view: views.includes(view as View) ? (view as View) : 'overview', item, tab };
  } catch {
    return { view: 'overview' };
  }
}
export function useRouter() {
  const [route, setRoute] = useState(read),
    current = useRef(route),
    guard = useDraftGuard();
  current.current = route;
  const navigate = useCallback(
    async (next: Route) => {
      if (href(next) === href(current.current)) return;
      if (!(await guard())) return;
      history.pushState(null, '', href(next));
      setRoute(next);
    },
    [guard],
  );
  useEffect(() => {
    const changed = () => {
      const next = read();
      if (href(next) === href(current.current)) return;
      void guard().then((allowed) => {
        if (allowed) setRoute(next);
        else history.pushState(null, '', href(current.current));
      });
    };
    window.addEventListener('hashchange', changed);
    return () => window.removeEventListener('hashchange', changed);
  }, [guard]);
  useEffect(() => {
    document.title = `${route.item || route.view[0].toUpperCase() + route.view.slice(1)} · MCP Hub`;
    window.scrollTo(0, 0);
  }, [route]);
  return { route, navigate };
}
export type Navigate = (route: Route) => Promise<void>;
