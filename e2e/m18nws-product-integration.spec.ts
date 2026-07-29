import { expect, test, type Page } from "@playwright/test";

const productRoutes = ["/", "/deal-room", "/protocol"] as const;

async function visibleStyleViolations(page: Page) {
  return page.locator(".product-shell *").evaluateAll((elements) =>
    elements
      .filter((element) => {
        const node = element as HTMLElement;
        const style = getComputedStyle(node);
        return node.getClientRects().length > 0 && style.visibility !== "hidden";
      })
      .filter((element) => getComputedStyle(element).boxShadow !== "none")
      .map((element) => ({
        tag: element.tagName.toLowerCase(),
        className: element.getAttribute("class") ?? "",
        shadow: getComputedStyle(element).boxShadow,
      })),
  );
}

async function visibleViewportText(page: Page) {
  return page.locator(".product-shell").evaluate((root) => {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const fragments: string[] = [];

    while (walker.nextNode()) {
      const node = walker.currentNode as Text;
      const value = node.textContent?.replace(/\s+/g, " ").trim();
      const parent = node.parentElement;
      if (!value || !parent || parent.closest('[aria-hidden="true"]')) continue;
      if (parent.closest("details:not([open])") && !parent.closest("summary")) continue;

      const style = getComputedStyle(parent);
      if (style.display === "none" || style.visibility === "hidden") continue;

      const range = document.createRange();
      range.selectNodeContents(node);
      const intersectsViewport = Array.from(range.getClientRects()).some(
        (rect) => rect.bottom > 0 && rect.top < window.innerHeight && rect.right > 0 && rect.left < window.innerWidth,
      );
      if (intersectsViewport) fragments.push(value);
    }

    return fragments.join(" ").replace(/\s+/g, " ").trim();
  });
}

test.describe("M-18NWS product integration", () => {
  test("the shared product language reaches every real surface without visual noise", async ({ page }) => {
    for (const path of productRoutes) {
      await page.goto(path);

      const shell = page.locator(".product-shell");
      await expect(shell).toBeVisible();
      const contract = await shell.evaluate((element) => {
        const style = getComputedStyle(element);
        return {
          ground: style.getPropertyValue("--nws-ground").trim(),
          ink: style.getPropertyValue("--nws-ink").trim(),
          receivable: style.getPropertyValue("--nws-receivable").trim(),
          protection: style.getPropertyValue("--nws-protection").trim(),
          action: style.getPropertyValue("--nws-action").trim(),
          fontFamily: style.fontFamily,
        };
      });

      expect(contract).toMatchObject({
        ground: "#f3f4ef",
        ink: "#12141a",
        receivable: "#006c9c",
        protection: "#d62e68",
        action: "#6750d8",
      });
      expect(contract.fontFamily.toLowerCase()).toContain("archivo");
      expect(await visibleStyleViolations(page)).toEqual([]);

      const rootlines = page.locator(".product-shell .rootline");
      for (let index = 0; index < await rootlines.count(); index += 1) {
        await expect(rootlines.nth(index)).toBeHidden();
      }

      const viewport = page.viewportSize();
      const documentWidth = await page.evaluate(() => ({
        client: document.documentElement.clientWidth,
        scroll: document.documentElement.scrollWidth,
      }));
      expect(documentWidth.scroll).toBeLessThanOrEqual((viewport?.width ?? documentWidth.client) + 1);
    }
  });

  test("decision, responsibility and accounting domains lead the participant view", async ({ page }) => {
    await page.goto("/deal-room");

    const firstView = page.getByTestId("participant-first-view");
    await expect(page.getByRole("heading", { name: /Your receivable has not moved/i })).toBeVisible();
    await expect(page.getByText("You have no action.", { exact: true })).toBeVisible();
    await expect(page.getByTestId("participant-deadline")).toContainText("Facility B");
    await expect(page.getByTestId("participant-deadline")).toContainText("12:00");
    await expect(firstView).toHaveAttribute("data-readiness-verdict", "WRONG_ROLE");

    const firstLevelText = await firstView.innerText();
    const firstLevelWords = firstLevelText.match(/[A-Za-zÀ-ÿ0-9]+(?:[’'.,:/-][A-Za-zÀ-ÿ0-9]+)*/g) ?? [];
    expect(firstLevelWords.length).toBeLessThanOrEqual(80);
    expect(firstLevelText.match(/Facility B/g)).toHaveLength(1);
    expect(firstLevelText.match(/12:00/g)).toHaveLength(1);
    expect(firstLevelText).not.toMatch(/invoice root|\bfolio\b|blocking gate|unlock|gate vector|0x[a-f0-9]+|MRD-|P[–-]CP/i);
    await expect(firstView.locator("time")).toHaveCount(1);

    const receivable = page.locator('.participant-domain-pair [data-domain="receivable"]');
    const protection = page.locator('.participant-domain-pair [data-domain="protection"]');
    const domainStyles = await Promise.all([
      receivable.evaluate((element) => getComputedStyle(element).backgroundColor),
      protection.evaluate((element) => getComputedStyle(element, "::before").backgroundColor),
    ]);
    expect(domainStyles).toEqual(["rgb(0, 108, 156)", "rgb(214, 46, 104)"]);
    await expect(receivable.locator("p")).toHaveCount(2);
    await expect(protection.locator("p")).toHaveCount(2);

    const why = page.getByTestId("participant-why");
    const evidence = page.getByTestId("participant-evidence");
    await expect(why).not.toHaveAttribute("open", "");
    await expect(evidence).not.toHaveAttribute("open", "");
    await expect(page.getByTestId("participant-primary-action")).toHaveAttribute("href", "/#portfolio");

    const viewportText = await visibleViewportText(page);
    const viewportWords = viewportText.match(/[A-Za-zÀ-ÿ0-9]+(?:[’'.,:/-][A-Za-zÀ-ÿ0-9]+)*/g) ?? [];
    expect(viewportWords.length).toBeLessThanOrEqual(80);
    expect(viewportText.match(/Facility B/g)).toHaveLength(1);
    expect(viewportText.match(/12:00/g)).toHaveLength(1);

    await page.getByTestId("participant-review-action").click();
    await expect(why).toHaveAttribute("open", "");
    await expect(why.locator('[data-readiness-verdict="WRONG_ROLE"]')).toBeVisible();
    await evidence.locator(":scope > summary").click();
    await expect(why).not.toHaveAttribute("open", "");
    await expect(evidence).toHaveAttribute("open", "");
    await expect(page.getByRole("heading", { name: "Configured scenario, not an observed transaction", exact: true })).toBeVisible();
  });

  test("product navigation produces a visible, focusable result and participant context stays folded", async ({ page }) => {
    await page.goto("/");

    const workspaceNavigation = page.getByRole("navigation", { name: "Originator navigation" });
    const workspaceLocation = workspaceNavigation.getByText("Workspace", { exact: true });
    await expect(workspaceLocation).toHaveAttribute("aria-current", "page");
    await expect(workspaceLocation).not.toHaveAttribute("href");

    await workspaceNavigation.getByRole("link", { name: "Portfolio", exact: true }).click();
    await expect(page).toHaveURL(/\/#portfolio$/);
    await expect(page.locator("#portfolio")).toBeFocused();
    await expect(workspaceNavigation.getByRole("link", { name: "Portfolio", exact: true })).toHaveAttribute(
      "aria-current",
      "location",
    );

    await workspaceNavigation.getByRole("link", { name: "Evidence", exact: true }).click();
    const workspaceEvidence = page.locator("details#evidence");
    await expect(page).toHaveURL(/\/#evidence$/);
    await expect(workspaceEvidence).toHaveAttribute("open", "");
    await expect(workspaceEvidence.locator("summary")).toBeFocused();

    await page.goto("/deal-room");
    const participantNavigation = page.getByRole("navigation", { name: "Holder navigation" });
    await expect(participantNavigation.locator("a")).toHaveText(["← Portfolio"]);
    await expect(page.getByLabel("Holder role")).toBeVisible();

    const context = page.locator(".session-context details");
    await expect(context).not.toHaveAttribute("open", "");
    await expect(context.getByText("Monad testnet · 10143", { exact: true })).toBeHidden();
    await context.locator("summary").click();
    await expect(context).toHaveAttribute("open", "");
    await expect(context.getByText("Monad testnet · 10143", { exact: true })).toBeVisible();
    await expect(context).toContainText("0x4B7…A82");
    await expect(page.getByText("Synthetic · no real funds", { exact: true })).toBeVisible();
  });

  test("workspace and protocol keep their primary operational controls", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByTestId("workspace-interventions").getByRole("button")).toHaveCount(12);
    await expect(page.getByTestId("decision-deadline")).toBeVisible();
    const workspaceAction = page.getByTestId("primary-action");
    await expect(workspaceAction).toBeVisible();
    const workspaceActionBox = await workspaceAction.boundingBox();
    expect(workspaceActionBox?.height ?? 0).toBeGreaterThanOrEqual(44);
    if ((page.viewportSize()?.width ?? 1280) <= 720) {
      expect((workspaceActionBox?.y ?? Number.POSITIVE_INFINITY) + (workspaceActionBox?.height ?? 0))
        .toBeLessThanOrEqual(page.viewportSize()?.height ?? 844);
    }

    await page.goto("/protocol");
    await expect(page.locator('.protocol-record-row[data-selected="true"]')).toContainText("after_state_unavailable");
    await expect(page.locator(".protocol-runbook")).toContainText("Recovery runbook · no automatic retry");
    await expect(page.locator(".protocol-runbook")).toContainText("resumeSyntheticTransition()");
    const proofContrast = await page.evaluate(() => {
      const rail = document.querySelector<HTMLElement>(".protocol-diagnostic-rail");
      const command = Array.from(document.querySelectorAll<HTMLElement>(".protocol-runbook p"))
        .find((element) => element.textContent?.trim() === "resumeSyntheticTransition()");
      const clear = document.querySelector<HTMLElement>(
        '.protocol-diagnostic-rail .gate-item[data-gate-tone="pass"] .gate-label-line span',
      );
      if (!rail || !command || !clear) throw new Error("Protocol proof contrast samples are missing.");

      const channels = (color: string) => {
        const match = color.match(/[\d.]+/g);
        if (!match || match.length < 3) throw new Error(`Unsupported computed color: ${color}`);
        return match.slice(0, 3).map(Number).map((value) => {
          const normalized = value / 255;
          return normalized <= 0.04045
            ? normalized / 12.92
            : ((normalized + 0.055) / 1.055) ** 2.4;
        });
      };
      const luminance = (color: string) => {
        const [red, green, blue] = channels(color);
        return 0.2126 * red + 0.7152 * green + 0.0722 * blue;
      };
      const ratio = (foreground: string, background: string) => {
        const values = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
        return (values[0] + 0.05) / (values[1] + 0.05);
      };
      const background = getComputedStyle(rail).backgroundColor;
      return {
        command: ratio(getComputedStyle(command).color, background),
        clear: ratio(getComputedStyle(clear).color, background),
      };
    });
    expect(proofContrast.command).toBeGreaterThanOrEqual(4.5);
    expect(proofContrast.clear).toBeGreaterThanOrEqual(4.5);
    if ((page.viewportSize()?.width ?? 1280) <= 720) {
      const incidentBox = await page.getByTestId("protocol-incident-stage").boundingBox();
      const impactBox = await page.getByTestId("protocol-impact").boundingBox();
      const runbookBox = await page.getByTestId("protocol-runbook").boundingBox();
      const proofBox = await page.getByTestId("protocol-proof-stage").boundingBox();
      expect(incidentBox).not.toBeNull();
      expect(impactBox).not.toBeNull();
      expect(runbookBox).not.toBeNull();
      expect(proofBox).not.toBeNull();
      expect((impactBox?.y ?? 0) + (impactBox?.height ?? 0)).toBeLessThanOrEqual(runbookBox?.y ?? 0);
      expect((runbookBox?.y ?? 0) + (runbookBox?.height ?? 0)).toBeLessThanOrEqual(proofBox?.y ?? 0);

      const protocolActionBox = await page
        .locator(".protocol-runbook")
        .getByRole("button", { name: "Copy selected checklist", exact: true })
        .boundingBox();
      expect((protocolActionBox?.y ?? Number.POSITIVE_INFINITY) + (protocolActionBox?.height ?? 0))
        .toBeLessThanOrEqual(page.viewportSize()?.height ?? 844);
    }
  });
});
