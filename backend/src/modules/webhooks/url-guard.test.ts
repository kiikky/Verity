import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { isPrivateAddress, assertPublicHttpUrl } from "./url-guard.js";
import { HttpError } from "../../http-error.js";

describe("isPrivateAddress", () => {
  const cases: [string, boolean][] = [
    ["10.0.0.1", true],
    ["127.0.0.1", true],
    ["0.0.0.0", true],
    ["169.254.169.254", true],
    ["192.168.1.1", true],
    ["172.15.255.255", false],
    ["172.16.0.0", true],
    ["172.31.255.255", true],
    ["172.32.0.0", false],
    ["192.167.0.1", false],
    ["100.63.255.255", false],
    ["100.64.0.0", true],
    ["100.127.255.255", true],
    ["100.128.0.0", false],
    ["8.8.8.8", false],
    ["1.1.1.1", false],
    ["::1", true],
    ["::", true],
    ["fc00::1", true],
    ["fd12::1", true],
    ["fe80::1", true],
    ["::ffff:127.0.0.1", true],
    ["::ffff:10.0.0.1", true],
    ["2001:4860:4860::8888", false],
    ["2606:4700::1111", false],
  ];

  for (const [ip, expected] of cases) {
    test(`identifies ${ip} as ${expected ? "private" : "not private"}`, () => {
      assert.equal(isPrivateAddress(ip), expected);
    });
  }
});

describe("assertPublicHttpUrl", () => {
  test("throws 400 for not a url", async () => {
    await assert.rejects(
      () => assertPublicHttpUrl("not a url"),
      (e) => e instanceof HttpError && e.statusCode === 400 && e.message === "webhook url is not a valid URL"
    );
  });

  test("throws 400 for ftp protocol", async () => {
    await assert.rejects(
      () => assertPublicHttpUrl("ftp://example.com/x"),
      (e) => e instanceof HttpError && e.statusCode === 400 && e.message === "unsupported webhook protocol: ftp:"
    );
  });

  test("throws 400 for file protocol", async () => {
    await assert.rejects(
      () => assertPublicHttpUrl("file:///etc/passwd"),
      (e) => e instanceof HttpError && e.statusCode === 400 && e.message === "unsupported webhook protocol: file:"
    );
  });

  test("throws 400 for javascript protocol", async () => {
    await assert.rejects(
      () => assertPublicHttpUrl("javascript:alert(1)"),
      (e) => e instanceof HttpError && e.statusCode === 400 && e.message === "unsupported webhook protocol: javascript:"
    );
  });

  test("throws 400 for private IPv4 127.0.0.1", async () => {
    await assert.rejects(
      () => assertPublicHttpUrl("http://127.0.0.1/"),
      (e) => e instanceof HttpError && e.statusCode === 400 && e.message === "webhook host 127.0.0.1 resolves to a non-public address"
    );
  });

  test("throws 400 for private IPv4 with port and path", async () => {
    await assert.rejects(
      () => assertPublicHttpUrl("http://192.168.0.5:8080/a"),
      (e) => e instanceof HttpError && e.statusCode === 400 && e.message === "webhook host 192.168.0.5 resolves to a non-public address"
    );
  });

  test("throws 400 for private IPv6 [::1]", async () => {
    await assert.rejects(
      () => assertPublicHttpUrl("http://[::1]/"),
      (e) => e instanceof HttpError && e.statusCode === 400 && e.message === "webhook host ::1 resolves to a non-public address"
    );
  });

  test("resolves public IP literal https://8.8.8.8/hook", async () => {
    const url = await assertPublicHttpUrl("https://8.8.8.8/hook");
    assert.equal(url.href, "https://8.8.8.8/hook");
  });
});
