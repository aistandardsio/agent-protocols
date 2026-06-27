# AAuth Animated Infographic

Animated network diagram showing the AAuth human consent flow for LinkedIn and social media.

## Files

| File | Description |
|------|-------------|
| `aauth_flow_animated.html` | Animated HTML/SVG/CSS infographic |
| `capture-gif.js` | Node.js script to capture frames |
| `aauth_flow.gif` | Generated GIF (after running capture) |

## Quick Preview

Open `aauth_flow_animated.html` in a browser to preview the animation.

```bash
open aauth_flow_animated.html
```

## Creating the GIF

### Method 1: Puppeteer + ffmpeg (Recommended)

```bash
# Install dependencies
npm install puppeteer

# Capture frames
node capture-gif.js

# Convert to GIF with ffmpeg
cd frames
ffmpeg -framerate 30 -i frame_%04d.png \
  -vf "fps=15,scale=540:-1:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse" \
  ../aauth_flow.gif
```

### Method 2: Puppeteer + gifski (Better quality)

```bash
# Install gifski (macOS)
brew install gifski

# Capture frames
node capture-gif.js

# Convert to GIF
cd frames
gifski -o ../aauth_flow.gif --fps 15 --width 540 frame_*.png
```

### Method 3: Screen Recording

1. Open `aauth_flow_animated.html` in browser
2. Use macOS screen recording (Cmd+Shift+5) or OBS
3. Record one full 6-second cycle
4. Convert to GIF using online tools or:
   ```bash
   ffmpeg -i recording.mov -vf "fps=15,scale=540:-1" output.gif
   ```

## LinkedIn Specifications

| Format | Recommended Size |
|--------|------------------|
| Square | 1080×1080 px |
| Landscape | 1200×628 px |
| File size | <5MB for GIF, <200MB for video |
| Duration | 3-10 seconds |

The HTML is set to 1080×1080 (square) by default. Modify `.container` in CSS to change dimensions.

## Customization

### Change Colors

Edit CSS variables in the `<style>` block:

```css
/* Primary accent color */
#64ffda  /* Teal/cyan */

/* Background gradient */
#1a1a2e, #16213e, #0f3460  /* Dark blue gradient */

/* Text colors */
#fff     /* White - headings */
#8892b0  /* Gray - secondary text */
```

### Change Animation Speed

Modify the animation duration in CSS:

```css
/* Current: 6 seconds per cycle */
animation: moveAlongPath1 6s ease-in-out infinite;

/* Faster: 4 seconds */
animation: moveAlongPath1 4s ease-in-out infinite;
```

Also update `CONFIG.duration` in `capture-gif.js` to match.

### Add More Nodes

Add new `<g class="node">` elements in the SVG and corresponding connection paths.

## Animation Flow

The infographic shows 4 phases:

1. **Authorization Request** - Agent → Person Server
2. **Human Consent** - Person Server → Human → Person Server
3. **Token Issuance** - Person Server → Agent
4. **Resource Access** - Agent → Resource Server

Each phase is highlighted in sequence with moving dots along the connection paths.

## Alternative Formats

### MP4 Video

For higher quality, export as MP4 instead of GIF:

```bash
cd frames
ffmpeg -framerate 30 -i frame_%04d.png \
  -c:v libx264 -pix_fmt yuv420p \
  -vf "scale=1080:1080" \
  ../aauth_flow.mp4
```

### Lottie (for web embedding)

Use Bodymovin or similar tools to convert to Lottie JSON for web embedding with interactivity.

## Credits

- AAuth Protocol: [draft-hardt-oauth-aauth-protocol](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/)
- AIStandards.io
