#!/bin/sh
# Cut the cover-up video into the README hero: still beats held, motion only where it tells the story.
# The video drifts and has film grain, so every moving frame is a full GIF frame; held stills keep the GIF small.
# usage: docs/demo/cut_hero.sh docs/demo/cover-up.mp4 docs/demo/cover-up.gif   (needs ffmpeg)
set -e
V=$1; OUT=$2; W=${3:-960}; FPS=10
F=""; L=""; i=0
add() { F="$F$1,fps=$FPS,scale=$W:-1:flags=lanczos,hqdn3d=2:2:20:20[v$i];"; L="$L[v$i]"; i=$((i+1)); }
still() { add "[0:v]trim=start=$1:duration=0.05,setpts=PTS-STARTPTS,tpad=stop_mode=clone:stop_duration=$2"; }
clip() { add "[0:v]trim=$1:$2,setpts=(PTS-STARTPTS)/$3,tpad=stop_mode=clone:stop_duration=$4"; }
still 5.8 2.6       # An AI agent deleted 43 orders. Then it hid the evidence.
clip 37.0 42.95 2.2 1.8   # the injected ticket types out
still 50.6 2.1      # Tracekit flags the delete and signs it
still 62.6 2.3      # the cover-up: the agent edits Tracekit's signed record
still 70.4 1.9      # grep finds no delete; the log shows two lookups
still 75.9 2.0      # but the database holds 85 orders
still 80.5 1.6      # the viewer marks the run FAILED
clip 84.0 85.7 1.0 2.3   # the verifier report, stamped FAILED
still 99.6 0.05     # Can edit the file. Can't hide the edit.
ffmpeg -nostdin -v error -y -i "$V" -filter_complex "${F}${L}concat=n=$i:v=1:a=0,mpdecimate=hi=64*4:lo=64*2:frac=0.2,split[a][b];[a]palettegen=max_colors=${COLORS:-128}:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle" -fps_mode vfr -final_delay 300 "$OUT"
