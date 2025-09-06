# Maintainer: tazdev-ops <your-email@example.com>
pkgname=gnaw-git
_pkgname=gnaw
pkgver=r1.0.0
pkgrel=1
pkgdesc="One-click MASQUE-in-MASQUE (outer usque + sing-box TUN + inner usque) with a minimal GTK4 GUI"
arch=('any')
url="https://github.com/tazdev-ops/gnaw"
license=('MIT')  # adjust if different
depends=(
  'python'
  'python-gobject'
  'gtk4'
  'polkit'
  'usque'
  'sing-box'   # satisfied by sing-box-bin, sing-box-git, sing-box-beta*, etc. (those packages provide 'sing-box')
)
makedepends=('git')
optdepends=(
  'python-requests: WARP/trace checks (optional)'
  'aioquic: QUIC scanner (optional)'
)
provides=('gnaw')
conflicts=('gnaw')
install="${pkgname}.install"
source=("git+https://github.com/tazdev-ops/gnaw.git")
sha256sums=('SKIP')

pkgver() {
  cd "${srcdir}/${_pkgname}"
  # vX.Y.Z -> X.Y.Z; fallback to r<N>.g<hash>
  (git describe --tags --long 2>/dev/null | sed 's/^v//; s/-/./g') || echo "r$(git rev-list --count HEAD).g$(git rev-parse --short HEAD)"
}

package() {
  cd "${srcdir}/${_pkgname}"

  # Binaries
  install -Dm755 "gnaw.py" "${pkgdir}/usr/bin/gnaw"
  install -Dm755 "gnaw-gui.py" "${pkgdir}/usr/bin/gnaw-gui"

  # Admin helper (accept either filename)
  local _admin="gnaw_admin.py"
  [[ -f "gnaw-admin.py" ]] && _admin="gnaw-admin.py"
  install -Dm755 "${_admin}" "${pkgdir}/usr/lib/gnaw/gnaw_admin.py"

  # Desktop + Polkit
  install -Dm644 "gnaw.desktop" "${pkgdir}/usr/share/applications/gnaw.desktop"
  install -Dm644 "dev.gnaw.admin.policy" "${pkgdir}/usr/share/polkit-1/actions/dev.gnaw.admin.policy"

  # Icons — prefer processed assets, fallback to any file with same name at repo root if needed
  for s in 512 256; do
    if [[ -f "assets/gnaw-${s}.png" ]]; then
      install -Dm644 "assets/gnaw-${s}.png" "${pkgdir}/usr/share/icons/hicolor/${s}x${s}/apps/gnaw.png"
    elif [[ -f "gnaw-${s}.png" ]]; then
      install -Dm644 "gnaw-${s}.png" "${pkgdir}/usr/share/icons/hicolor/${s}x${s}/apps/gnaw.png"
    elif [[ -f "g-devil-app-logo.png" ]]; then
      # last-resort fallback (desktop will scale)
      install -Dm644 "g-devil-app-logo.png" "${pkgdir}/usr/share/icons/hicolor/${s}x${s}/apps/gnaw.png"
    fi
  done

  # In-app logo
  if [[ -f "assets/gnaw-inner.png" ]]; then
    install -Dm644 "assets/gnaw-inner.png" "${pkgdir}/usr/share/gnaw/gnaw-inner.png"
  elif [[ -f "black-devil-on-white-background.png" ]]; then
    install -Dm644 "black-devil-on-white-background.png" "${pkgdir}/usr/share/gnaw/gnaw-inner.png"
  fi

  # License (optional)
  if [[ -f "LICENSE" ]]; then
    install -Dm644 "LICENSE" "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
  fi
}
