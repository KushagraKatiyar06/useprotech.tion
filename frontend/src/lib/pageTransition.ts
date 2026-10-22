// Shared by every "navigate to another route" link that wants a fade instead
// of an instant jump cut — Header's Home link, the landing page's Start
// link. Fades #page-content only (not the GlobalBackdrop behind it — see
// layout.tsx), so the FloatingLines/circuit-wires backdrop keeps flowing
// continuously straight through the navigation instead of blinking.
export function navigateWithFade(push: (href: string) => void, href: string): void {
  const el = document.getElementById('page-content');
  el?.classList.add('page-leaving');
  setTimeout(() => {
    push(href);
    setTimeout(() => el?.classList.remove('page-leaving'), 60);
  }, 260);
}
