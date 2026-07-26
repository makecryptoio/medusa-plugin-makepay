import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { chromium } from "playwright";

const officialOrigin = "https://www.makecrypto.io";
const documentationPath = "/documentation/makepay/apps/medusa";
const evidence = [
  {
    caption:
      "Medusa Admin MakePay settings connected to a sandbox company with OAuth and installation webhook health.",
    filename: "connected-makepay-settings.png",
  },
  {
    caption:
      "Medusa Admin MakePay payment list showing the installation-scoped local payment projection.",
    filename: "makepay-payments-list.png",
  },
  {
    caption:
      "Medusa order details showing the MakePay payment widget and read-only reconciliation controls.",
    filename: "makepay-order-widget.png",
  },
  {
    caption:
      "MakePay sandbox hosted checkout opened from the Medusa storefront order flow.",
    filename: "makepay-sandbox-checkout.png",
  },
];

function fail(message) {
  throw new Error(message);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function publicPath(filename) {
  return `/images/documentation/apps/medusa/${filename}`;
}

function parseManifestArgument(argv) {
  if (
    argv.length !== 2 ||
    argv[0] !== "--manifest" ||
    !argv[1] ||
    argv[1].startsWith("--")
  ) {
    fail(
      "Usage: node official-documentation-gate.mjs --manifest .github/assets/vX.Y.Z/manifest.json",
    );
  }
  return resolve(argv[1]);
}

async function main() {
  const manifestPath = parseManifestArgument(process.argv.slice(2));
  const manifestEntry = await lstat(manifestPath);
  if (
    manifestEntry.isSymbolicLink() ||
    !manifestEntry.isFile() ||
    manifestEntry.nlink !== 1 ||
    (typeof process.getuid === "function" &&
      manifestEntry.uid !== process.getuid())
  ) {
    fail("Official documentation rendering requires a trusted manifest file");
  }
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const manifestEvidence = Array.isArray(manifest.evidence)
    ? manifest.evidence
    : [];
  const hashes = new Map(
    manifestEvidence.map((entry) => [entry.filename, entry.sha256]),
  );
  if (
    manifest.schemaVersion !== 3 ||
    manifest.mode !== "real-sandbox" ||
    manifest.completionAttestation?.status !== "accepted" ||
    manifestEvidence.length !== evidence.length ||
    new Set(manifestEvidence.map((entry) => entry.filename)).size !==
      evidence.length ||
    new Set(manifestEvidence.map((entry) => entry.sha256)).size !==
      evidence.length ||
    evidence.some(
      ({ filename }) => !/^[a-f0-9]{64}$/.test(hashes.get(filename) || ""),
    )
  ) {
    fail("Official documentation rendering requires the accepted manifest");
  }

  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({
      baseURL: officialOrigin,
      colorScheme: "dark",
      serviceWorkers: "block",
      viewport: { height: 960, width: 1440 },
    });
    await context.setExtraHTTPHeaders({
      "cache-control": "no-cache, no-store",
      pragma: "no-cache",
    });
    const page = await context.newPage();
    const pageErrors = [];
    const failedImageRequests = [];
    const imageResponses = new Map();
    page.on("pageerror", (error) => pageErrors.push(error.message));
    page.on("requestfailed", (request) => {
      const pathname = new URL(request.url()).pathname;
      if (evidence.some(({ filename }) => pathname === publicPath(filename))) {
        failedImageRequests.push(pathname);
      }
    });
    page.on("response", (response) => {
      const pathname = new URL(response.url()).pathname;
      if (evidence.some(({ filename }) => pathname === publicPath(filename))) {
        imageResponses.set(pathname, [
          ...(imageResponses.get(pathname) || []),
          response,
        ]);
      }
    });

    const documentationUrl = `${officialOrigin}${documentationPath}`;
    const navigation = await page.goto(documentationUrl, {
      waitUntil: "domcontentloaded",
    });
    if (
      !navigation ||
      navigation.url() !== documentationUrl ||
      navigation.status() !== 200 ||
      navigation.request().redirectedFrom() ||
      (navigation.headers()["content-type"] || "")
        .split(";", 1)[0]
        .trim()
        .toLowerCase() !== "text/html"
    ) {
      fail("Official MakeCrypto Medusa page did not navigate directly");
    }
    await page
      .locator('[data-docs-product-ready="true"]')
      .waitFor({ state: "visible", timeout: 30_000 });
    if (page.url() !== documentationUrl) {
      fail("Official MakeCrypto Medusa page changed its canonical URL");
    }
    if ((await page.locator("[data-nextjs-dialog-overlay]").count()) !== 0) {
      fail(
        "Official MakeCrypto Medusa page rendered a framework error overlay",
      );
    }

    for (const { caption, filename } of evidence) {
      const expectedPath = publicPath(filename);
      const figure = page.locator(
        `[data-makepay-medusa-evidence="${filename}"]`,
      );
      if ((await figure.count()) !== 1) {
        fail(`Official documentation must render one figure: ${filename}`);
      }
      await figure.evaluate((element) =>
        element.scrollIntoView({ behavior: "auto", block: "center" }),
      );
      await page.evaluate(
        () =>
          new Promise((resolveFrame) =>
            requestAnimationFrame(() => requestAnimationFrame(resolveFrame)),
          ),
      );
      await figure.waitFor({ state: "visible", timeout: 15_000 });
      const image = figure.locator(`img[alt="${caption}"]`);
      if ((await image.count()) !== 1 || !(await image.isVisible())) {
        fail(`Official documentation image is not visible: ${filename}`);
      }
      await image.evaluate(async (element) => {
        if (element.complete) return;
        await new Promise((resolveLoad, rejectLoad) => {
          const timeout = window.setTimeout(
            () => rejectLoad(new Error("Image decode timed out")),
            15_000,
          );
          element.addEventListener(
            "load",
            () => {
              window.clearTimeout(timeout);
              resolveLoad();
            },
            { once: true },
          );
          element.addEventListener(
            "error",
            () => {
              window.clearTimeout(timeout);
              rejectLoad(new Error("Image decode failed"));
            },
            { once: true },
          );
        });
      });
      const captionElement = figure.locator("figcaption");
      if (!(await captionElement.isVisible())) {
        fail(`Official documentation caption is hidden: ${filename}`);
      }
      const visibleCaption = (await captionElement.innerText())
        .replace(/\s+/g, " ")
        .trim();
      if (visibleCaption !== caption) {
        fail(`Official documentation caption changed: ${filename}`);
      }
      const captionState = await captionElement.evaluate((element) => {
        const rectangle = element.getBoundingClientRect();
        let effectiveOpacity = 1;
        let stylesSafe = true;
        for (let current = element; current; current = current.parentElement) {
          const style = getComputedStyle(current);
          const opacity = Number(style.opacity);
          effectiveOpacity *= Number.isFinite(opacity) ? opacity : 1;
          if (
            style.display === "none" ||
            style.visibility !== "visible" ||
            style.contentVisibility === "hidden" ||
            style.filter !== "none"
          ) {
            stylesSafe = false;
          }
        }
        const hit = document.elementFromPoint(
          rectangle.left + rectangle.width / 2,
          rectangle.top + rectangle.height / 2,
        );
        return {
          effectiveOpacity,
          height: rectangle.height,
          inViewport:
            rectangle.left >= 0 &&
            rectangle.top >= 0 &&
            rectangle.right <= window.innerWidth &&
            rectangle.bottom <= window.innerHeight,
          stylesSafe,
          unobscured: Boolean(hit && element.contains(hit)),
          width: rectangle.width,
        };
      });
      if (
        captionState.width < 100 ||
        captionState.height < 12 ||
        captionState.effectiveOpacity < 0.98 ||
        !captionState.inViewport ||
        !captionState.stylesSafe ||
        !captionState.unobscured
      ) {
        fail(`Official documentation caption is not readable: ${filename}`);
      }
      const captionScreenshot = await captionElement.screenshot({
        animations: "disabled",
      });
      const captionPixels = await captionElement.evaluate(
        async (_element, screenshotBase64) => {
          const binary = atob(screenshotBase64);
          const bytes = Uint8Array.from(binary, (value) => value.charCodeAt(0));
          const screenshot = await createImageBitmap(
            new Blob([bytes], { type: "image/png" }),
          );
          const canvas = document.createElement("canvas");
          canvas.width = 64;
          canvas.height = 16;
          const context = canvas.getContext("2d", { willReadFrequently: true });
          context.drawImage(screenshot, 0, 0, canvas.width, canvas.height);
          const pixels = context.getImageData(
            0,
            0,
            canvas.width,
            canvas.height,
          ).data;
          const buckets = new Set();
          let minimum = 255;
          let maximum = 0;
          for (let offset = 0; offset < pixels.length; offset += 4) {
            minimum = Math.min(
              minimum,
              pixels[offset],
              pixels[offset + 1],
              pixels[offset + 2],
            );
            maximum = Math.max(
              maximum,
              pixels[offset],
              pixels[offset + 1],
              pixels[offset + 2],
            );
            buckets.add(
              (pixels[offset] >> 5) * 64 +
                (pixels[offset + 1] >> 5) * 8 +
                (pixels[offset + 2] >> 5),
            );
          }
          return { colorBuckets: buckets.size, range: maximum - minimum };
        },
        captionScreenshot.toString("base64"),
      );
      if (captionPixels.colorBuckets < 3 || captionPixels.range < 24) {
        fail(`Official documentation caption is visually blank: ${filename}`);
      }
      const figureBox = await figure.boundingBox();
      if (
        !figureBox ||
        figureBox.x < 0 ||
        figureBox.y < 0 ||
        figureBox.x + figureBox.width > 1440 ||
        figureBox.y + figureBox.height > 960
      ) {
        fail(`Official documentation figure is clipped: ${filename}`);
      }
      const imageState = await image.evaluate((element) => {
        const imageElement = element;
        const rectangle = imageElement.getBoundingClientRect();
        let effectiveOpacity = 1;
        let stylesSafe = true;
        for (
          let current = imageElement;
          current;
          current = current.parentElement
        ) {
          const style = getComputedStyle(current);
          const opacity = Number(style.opacity);
          effectiveOpacity *= Number.isFinite(opacity) ? opacity : 1;
          if (
            style.display === "none" ||
            style.visibility !== "visible" ||
            style.contentVisibility === "hidden" ||
            style.filter !== "none"
          ) {
            stylesSafe = false;
          }
        }
        const hit = document.elementFromPoint(
          rectangle.left + rectangle.width / 2,
          rectangle.top + rectangle.height / 2,
        );
        return {
          complete: imageElement.complete,
          currentSrc: imageElement.currentSrc,
          effectiveOpacity,
          height: imageElement.naturalHeight,
          inViewport:
            rectangle.left >= 0 &&
            rectangle.top >= 0 &&
            rectangle.right <= window.innerWidth &&
            rectangle.bottom <= window.innerHeight,
          renderedHeight: rectangle.height,
          renderedWidth: rectangle.width,
          stylesSafe,
          unobscured: Boolean(hit && imageElement.contains(hit)),
          width: imageElement.naturalWidth,
        };
      });
      const currentSource = new URL(imageState.currentSrc);
      if (
        !imageState.complete ||
        imageState.width !== 1440 ||
        imageState.height !== 900 ||
        imageState.renderedWidth < 400 ||
        imageState.renderedHeight < 250 ||
        imageState.renderedWidth / imageState.renderedHeight < 1.5 ||
        imageState.renderedWidth / imageState.renderedHeight > 1.7 ||
        imageState.effectiveOpacity < 0.98 ||
        !imageState.stylesSafe ||
        !imageState.inViewport ||
        !imageState.unobscured ||
        currentSource.origin !== officialOrigin ||
        currentSource.pathname !== expectedPath ||
        currentSource.search ||
        currentSource.hash
      ) {
        fail(
          `Official documentation image is not publication-safe: ${filename}`,
        );
      }
      const renderedImage = await image.screenshot({ animations: "disabled" });
      const visualComparison = await image.evaluate(
        async (element, screenshotBase64) => {
          const binary = atob(screenshotBase64);
          const bytes = Uint8Array.from(binary, (value) => value.charCodeAt(0));
          const screenshot = await createImageBitmap(
            new Blob([bytes], { type: "image/png" }),
          );
          const sample = (source) => {
            const canvas = document.createElement("canvas");
            canvas.width = 32;
            canvas.height = 20;
            const context = canvas.getContext("2d", {
              willReadFrequently: true,
            });
            context.drawImage(source, 0, 0, canvas.width, canvas.height);
            return context.getImageData(0, 0, canvas.width, canvas.height).data;
          };
          const expectedPixels = sample(element);
          const renderedPixels = sample(screenshot);
          const buckets = new Set();
          let difference = 0;
          for (let offset = 0; offset < expectedPixels.length; offset += 4) {
            difference +=
              Math.abs(expectedPixels[offset] - renderedPixels[offset]) +
              Math.abs(
                expectedPixels[offset + 1] - renderedPixels[offset + 1],
              ) +
              Math.abs(expectedPixels[offset + 2] - renderedPixels[offset + 2]);
            buckets.add(
              (renderedPixels[offset] >> 5) * 64 +
                (renderedPixels[offset + 1] >> 5) * 8 +
                (renderedPixels[offset + 2] >> 5),
            );
          }
          return {
            colorBuckets: buckets.size,
            meanChannelDifference:
              difference / ((expectedPixels.length / 4) * 3),
          };
        },
        renderedImage.toString("base64"),
      );
      if (
        visualComparison.colorBuckets < 8 ||
        visualComparison.meanChannelDifference > 18
      ) {
        fail(
          `Official documentation image is hidden or visually obscured: ${filename}`,
        );
      }

      const responses = imageResponses.get(expectedPath) || [];
      if (responses.length !== 1) {
        fail(`Official image must have one uncached response: ${filename}`);
      }
      const response = responses[0];
      const responseUrl = new URL(response.url());
      const contentType = (response.headers()["content-type"] || "")
        .split(";", 1)[0]
        .trim()
        .toLowerCase();
      if (
        responseUrl.origin !== officialOrigin ||
        responseUrl.pathname !== expectedPath ||
        responseUrl.search ||
        responseUrl.hash ||
        response.status() !== 200 ||
        response.request().redirectedFrom() ||
        response.fromServiceWorker() ||
        contentType !== "image/png" ||
        sha256(await response.body()) !== hashes.get(filename)
      ) {
        fail(`Official image response is not exact: ${filename}`);
      }
    }
    if (failedImageRequests.length || pageErrors.length) {
      fail(
        `Official documentation has failed images or runtime errors: ${[
          ...failedImageRequests,
          ...pageErrors,
        ].join("; ")}`,
      );
    }
    await context.close();
  } finally {
    await browser.close();
  }
  console.log(
    "Official MakeCrypto Medusa documentation render gate passed (4 images).",
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
