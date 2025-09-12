# Maintainer: mativiters
pkgname=gnaw
pkgver=0.1.0
pkgrel=1
pkgdesc="Gnaw — MASQUE wrapper + MiM + admin helper + GTK GUI (single file)"
arch=('any')
url="https://github.com/tazdev-ops/gnaw"
license=('custom')
depends=(
  'python'
  'usque'        # AUR: usque
)
optdepends=(
  'gtk4: GUI'
  'python-gobject: GTK4 Python bindings for the GUI'
  'polkit: pkexec authentication (used by GUI/admin helper)'
  'sing-box: Masque-in-Masque (TUN) support'
  'python-requests: optional inner WARP trace'
  'python-pysocks: SOCKS support for requests'
  'xdg-utils: xdg-open for opening logs'
  'libcap: getcap for rootless capability checks'
)
source=(
  'gnaw.py'
  'gnaw.desktop'
)
sha256sums=('SKIP' 'SKIP')

build() { :; }

package() {
  install -Dm755 "$srcdir/gnaw.py" "$pkgdir/usr/bin/gnaw"
  install -Dm644 "$srcdir/gnaw.desktop" "$pkgdir/usr/share/applications/gnaw.desktop"
}
