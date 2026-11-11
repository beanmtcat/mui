import type { Node, Route, Server } from "../api";
import countryCenters from "../globe-data/country-centers.json";
import { cityTable, regionTable, type PlaceEntry } from "./geo-places";

export type Point = [longitude: number, latitude: number];
export type ServerPlace = { point: Point; precision: "city" | "country" };
export type RouteSegment = { from: string; to: string; routeIds: string[]; routeNames: string[]; active: boolean };

const normalize = (value: string) =>
  value.normalize("NFKC").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[\s._\-,/()（）·'"’]+/g, "");

const stripSuffix = (value: string) => {
  const cjk = value.replace(/(特别行政区|维吾尔自治区|壮族自治区|回族自治区|自治区|自治州|特别自治道|特别市|广域市|联邦直辖区|省|市|县|州|府)$/, "");
  if (cjk !== value && cjk.length >= 2) return cjk;
  const en = value.replace(/(metropolitancity|specialcity|prefecture|province|state|county|city)$/, "");
  return en !== value && en.length >= 4 ? en : value;
};

type PlaceIndex = {
  exact: Map<string, Point>;
  byCountry: Map<string, [name: string, point: Point, ascii: boolean][]>;
};

function buildIndex(table: PlaceEntry[]): PlaceIndex {
  const exact = new Map<string, Point>();
  const byCountry = new Map<string, [name: string, point: Point, ascii: boolean][]>();
  for (const [country, point, ...names] of table) {
    const list = byCountry.get(country) || [];
    for (const raw of names) {
      const key = normalize(raw);
      if (!key) continue;
      exact.set(`${country}:${key}`, point);
      const ascii = /^[a-z0-9]+$/.test(key);
      if ((ascii ? key.length >= 4 : key.length >= 2) && !list.some((item) => item[0] === key)) {
        list.push([key, point, ascii]);
      }
    }
    byCountry.set(country, list);
  }
  for (const list of byCountry.values()) {
    list.sort((a, b) => b[0].length - a[0].length);
  }
  return { exact, byCountry };
}

const cityIndex = buildIndex(cityTable);
const regionIndex = buildIndex(regionTable);

function resolveExact(raw: string | undefined, country: string, index: PlaceIndex): Point | null {
  if (!raw?.trim() || !country) return null;
  for (const part of [raw, ...raw.split(/[,/|·]+/)]) {
    const norm = normalize(part);
    if (!norm) continue;
    for (const candidate of [norm, stripSuffix(norm)]) {
      const hit = index.exact.get(`${country}:${candidate}`);
      if (hit) return hit;
    }
  }
  return null;
}

function resolveSubstring(raw: string | undefined, country: string, index: PlaceIndex, guardDistrict = false): Point | null {
  if (!raw?.trim() || !country) return null;
  const norm = normalize(raw);
  const lower = raw.normalize("NFKC").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase();
  const words = lower.match(/[a-z]+/g) || [];
  const phrases = new Set<string>();
  for (let i = 0; i < words.length; i++) {
    let joined = "";
    for (let j = i; j < Math.min(words.length, i + 4); j++) {
      joined += words[j];
      phrases.add(joined);
      phrases.add(stripSuffix(joined));
    }
  }
  let best: { point: Point; len: number; pos: number } | null = null;
  for (const [name, point, ascii] of index.byCountry.get(country) || []) {
    if (best && name.length < best.len) break;
    if (ascii) {
      if (phrases.has(name)) return point;
      continue;
    }
    const pos = norm.indexOf(name);
    if (pos < 0) continue;
    if (guardDistrict && country === "CN" && /^[区區路街巷]/.test(norm.slice(pos + name.length))) continue;
    if (!best || pos < best.pos) best = { point, len: name.length, pos };
  }
  return best?.point || null;
}

const placeCache = new Map<string, ServerPlace | null>();

function computeServerPlace(rawCountry: string, region: string, city: string): ServerPlace | null {
  const country = rawCountry === "UK" ? "GB" : rawCountry;
  if (country === "US" && city && normalize(city).replace(/city$/, "") === "washington") {
    return { point: [-77.04, 38.91], precision: "city" };
  }
  for (const value of [city, region]) {
    if (!value.trim()) continue;
    const hit =
      resolveExact(value, country, cityIndex) ||
      resolveExact(value, country, regionIndex) ||
      resolveSubstring(value, country, cityIndex, true) ||
      resolveSubstring(value, country, regionIndex);
    if (hit) return { point: hit, precision: "city" };
  }
  const point = (countryCenters as unknown as Record<string, Point>)[rawCountry] || (countryCenters as unknown as Record<string, Point>)[country];
  return point ? { point, precision: "country" } : null;
}

export function serverPlace(server: Server): ServerPlace | null {
  const country = server.country?.toUpperCase() || "";
  const region = server.region || "";
  const city = server.city || "";
  const key = `${country}|${region}|${city}`;
  if (placeCache.has(key)) return placeCache.get(key) ?? null;
  const result = computeServerPlace(country, region, city);
  placeCache.set(key, result);
  return result;
}

export function routeSegments(routes: Route[], nodes: Node[], includeDisabled: boolean, routeId: string): RouteSegment[] {
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const segments = new Map<string, RouteSegment>();
  for (const route of routes) {
    if ((!includeDisabled && !route.enabled) || (routeId && route.id !== routeId)) continue;
    const exit = nodeById.get(route.nodeId)?.serverId;
    if (!exit) continue;
    const groups = [[route.entryServerId], ...route.hops.map((hop) => hop.serverIds), [exit]];
    for (let i = 0; i < groups.length - 1; i++) {
      for (const from of groups[i]) for (const to of groups[i + 1]) {
        if (!from || !to || from === to) continue;
        const key = `${from}\u0000${to}`;
        const current = segments.get(key) || { from, to, routeIds: [], routeNames: [], active: false };
        current.routeIds.push(route.id);
        current.routeNames.push(route.name);
        current.active ||= route.enabled;
        segments.set(key, current);
      }
    }
  }
  return [...segments.values()];
}
