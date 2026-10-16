#!/bin/sh
# Renders the README graphics from these HTML pages at 2x with headless Chrome (fonts load from Google Fonts).
# usage: docs/readme/src/render.sh   (from the repository root)
set -e
cd "$(dirname "$0")"
CHROME=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
shot() {  # page out width height theme
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars --allow-file-access-from-files --force-device-scale-factor=2 \
    --window-size="$3,$4" --virtual-time-budget=6000 --default-background-color=00000000 \
    --screenshot="../$2" "file://$PWD/$1?theme=$5" 2>/dev/null
}
shot banner.html banner.png 1280 420 dark
for t in dark light; do
  shot how-it-works.html how-it-works-$t.png 1280 560 $t
  shot proof.html proof-$t.png 1280 560 $t
  shot works-with.html works-with-$t.png 1280 360 $t
done
# The flat graphics shrink about 4x as 256-colour PNGs; the banner's glow would band, so it stays full colour.
cd .. && python3 - <<'PY' || echo "Pillow not installed: PNGs left full colour"
from PIL import Image
for f in ["how-it-works-dark.png", "how-it-works-light.png", "proof-dark.png", "proof-light.png", "works-with-dark.png", "works-with-light.png"]:
    Image.open(f).quantize(colors=256, method=Image.Quantize.FASTOCTREE, dither=Image.Dither.NONE).save(f, optimize=True)
PY
