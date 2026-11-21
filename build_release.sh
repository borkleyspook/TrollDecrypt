set -e

rm -rf dist
mkdir dist

# Rootful .deb — full FoulDecrypt entitlements (Dopamine/AMFI bypass accepts them).
make clean
make package FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=
cp -p "`ls -dtr1 packages/* | tail -1`" ./dist/

# Rootless .deb — also needs the full entitlements, so build it WITHOUT
# PACKAGE_TIPA. (Previously it was built in the same pass as the .tipa, which
# would have given it the restricted TrollStore entitlements.)
make clean
make package FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless
cp -p "`ls -dtr1 packages/* | tail -1`" ./dist/

# .tipa — TrollStore re-signs this, so it must use the restricted entitlement
# set (see TrollDecrypt.tipa.entitlements). This pass also emits a .deb, but we
# intentionally only copy the .tipa here.
make clean
make package FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless PACKAGE_TIPA=1
cp -p TrollDecrypt.tipa ./dist/
