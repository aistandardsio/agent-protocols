#!/usr/bin/env node
/**
 * Capture animated HTML as GIF using Puppeteer
 *
 * Prerequisites:
 *   npm install puppeteer gifencoder png-js
 *   # or
 *   brew install ffmpeg  # for ffmpeg approach
 *
 * Usage:
 *   node capture-gif.js
 *
 * Alternative (using ffmpeg):
 *   node capture-gif.js --frames  # outputs PNG frames
 *   ffmpeg -framerate 30 -i frames/frame_%04d.png -vf "fps=15,scale=540:-1:flags=lanczos" output.gif
 */

const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');

const CONFIG = {
    htmlFile: 'aauth_flow_animated.html',
    outputDir: 'frames',
    outputGif: 'aauth_flow.gif',
    width: 1080,
    height: 1080,
    duration: 6000,  // 6 seconds (one full animation cycle)
    fps: 30,
    scale: 0.5,  // Scale down for smaller GIF (540x540)
};

async function captureFrames() {
    const browser = await puppeteer.launch({
        headless: 'new',
        args: ['--no-sandbox', '--disable-setuid-sandbox']
    });

    const page = await browser.newPage();

    await page.setViewport({
        width: CONFIG.width,
        height: CONFIG.height,
        deviceScaleFactor: 1,
    });

    const htmlPath = path.join(__dirname, CONFIG.htmlFile);
    await page.goto(`file://${htmlPath}`, { waitUntil: 'networkidle0' });

    // Create output directory
    const framesDir = path.join(__dirname, CONFIG.outputDir);
    if (!fs.existsSync(framesDir)) {
        fs.mkdirSync(framesDir, { recursive: true });
    }

    // Calculate frame count
    const frameCount = Math.floor(CONFIG.duration / 1000 * CONFIG.fps);
    const frameDelay = 1000 / CONFIG.fps;

    console.log(`Capturing ${frameCount} frames at ${CONFIG.fps} FPS...`);

    for (let i = 0; i < frameCount; i++) {
        const framePath = path.join(framesDir, `frame_${String(i).padStart(4, '0')}.png`);
        await page.screenshot({ path: framePath });

        if (i % 10 === 0) {
            console.log(`  Frame ${i + 1}/${frameCount}`);
        }

        await page.waitForTimeout(frameDelay);
    }

    await browser.close();

    console.log(`\nFrames saved to: ${framesDir}/`);
    console.log(`\nTo create GIF with ffmpeg:`);
    console.log(`  cd ${framesDir}`);
    console.log(`  ffmpeg -framerate ${CONFIG.fps} -i frame_%04d.png -vf "fps=15,scale=${Math.floor(CONFIG.width * CONFIG.scale)}:-1:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse" ../${CONFIG.outputGif}`);
    console.log(`\nOr with gifski (better quality):`);
    console.log(`  gifski -o ../${CONFIG.outputGif} --fps 15 --width ${Math.floor(CONFIG.width * CONFIG.scale)} frame_*.png`);
}

// Alternative: Use GIFEncoder directly (requires gifencoder package)
async function captureGifDirect() {
    const GIFEncoder = require('gifencoder');
    const PNG = require('png-js');

    // This approach requires more setup but produces GIF directly
    // For simplicity, the frame capture + ffmpeg approach is recommended
}

// Main
const args = process.argv.slice(2);
if (args.includes('--help') || args.includes('-h')) {
    console.log(`
AAuth Infographic GIF Generator

Usage:
  node capture-gif.js         Capture PNG frames
  node capture-gif.js --help  Show this help

After capturing frames, use ffmpeg or gifski to create the GIF.
`);
    process.exit(0);
}

captureFrames().catch(console.error);
