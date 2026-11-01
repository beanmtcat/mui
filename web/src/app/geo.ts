import type { Node, Route, Server } from "../api";
import countryCenters from "../globe-data/country-centers.json";

export type Point = [longitude: number, latitude: number];
export type ServerPlace = { point: Point; precision: "city" | "country" };
export type RouteSegment = { from: string; to: string; routeIds: string[]; routeNames: string[]; active: boolean };

// Common datacenter cities. Other cities fall back to the country marker;
// a geocoder would require sending server locations to an external service.
const cityPoints: Record<string, Point> = {
  "CN:上海": [121.47, 31.23], "CN:shanghai": [121.47, 31.23],
  "CN:北京": [116.4, 39.9], "CN:beijing": [116.4, 39.9],
  "CN:广州": [113.26, 23.13], "CN:guangzhou": [113.26, 23.13],
  "CN:深圳": [114.06, 22.54], "CN:shenzhen": [114.06, 22.54],
  "CN:成都": [104.07, 30.67], "CN:chengdu": [104.07, 30.67],
  "HK:香港": [114.17, 22.31], "HK:hongkong": [114.17, 22.31],
  "TW:台北": [121.57, 25.03], "TW:臺北": [121.57, 25.03], "TW:taipei": [121.57, 25.03],
  "TW:台中": [120.67, 24.15], "TW:taichung": [120.67, 24.15],
  "JP:东京": [139.69, 35.68], "JP:東京": [139.69, 35.68], "JP:tokyo": [139.69, 35.68],
  "JP:大阪": [135.5, 34.69], "JP:osaka": [135.5, 34.69],
  "SG:新加坡": [103.82, 1.35], "SG:singapore": [103.82, 1.35],
  "KR:首尔": [126.98, 37.57], "KR:seoul": [126.98, 37.57],
  "KR:釜山": [129.07, 35.18], "KR:busan": [129.07, 35.18],
  "MY:吉隆坡": [101.69, 3.14], "MY:kualalumpur": [101.69, 3.14],
  "MY:柔佛": [103.76, 1.49], "MY:johorbahru": [103.76, 1.49],
  "US:纽约": [-74.01, 40.71], "US:newyork": [-74.01, 40.71],
  "US:洛杉矶": [-118.24, 34.05], "US:losangeles": [-118.24, 34.05],
  "US:圣何塞": [-121.89, 37.34], "US:sanjose": [-121.89, 37.34],
  "US:西雅图": [-122.33, 47.61], "US:seattle": [-122.33, 47.61],
  "US:达拉斯": [-96.8, 32.78], "US:dallas": [-96.8, 32.78],
  "US:芝加哥": [-87.63, 41.88], "US:chicago": [-87.63, 41.88],
  "US:迈阿密": [-80.19, 25.76], "US:miami": [-80.19, 25.76],
  "DE:法兰克福": [8.68, 50.11], "DE:frankfurt": [8.68, 50.11],
  "CA:多伦多": [-79.38, 43.65], "CA:toronto": [-79.38, 43.65],
  "CA:温哥华": [-123.12, 49.28], "CA:vancouver": [-123.12, 49.28],
  "GB:伦敦": [-0.13, 51.51], "GB:london": [-0.13, 51.51],
  "NL:阿姆斯特丹": [4.9, 52.37], "NL:amsterdam": [4.9, 52.37],
  "FR:巴黎": [2.35, 48.86], "FR:paris": [2.35, 48.86],
  "AU:悉尼": [151.21, -33.87], "AU:sydney": [151.21, -33.87],
  "AU:墨尔本": [144.96, -37.81], "AU:melbourne": [144.96, -37.81],
  "UY:蒙得维的亚": [-56.16, -34.9], "UY:montevideo": [-56.16, -34.9],
  "RU:莫斯科": [37.62, 55.75], "RU:moscow": [37.62, 55.75],
  "IN:孟买": [72.88, 19.08], "IN:mumbai": [72.88, 19.08],
  "AE:迪拜": [55.27, 25.2], "AE:dubai": [55.27, 25.2],
  "TH:曼谷": [100.5, 13.76], "TH:bangkok": [100.5, 13.76],
  "VN:胡志明市": [106.7, 10.82], "VN:hochiminhcity": [106.7, 10.82],
  "PH:马尼拉": [120.98, 14.6], "PH:manila": [120.98, 14.6],
  "ID:雅加达": [106.85, -6.21], "ID:jakarta": [106.85, -6.21],
};

const normalize = (value: string) => value.normalize("NFKC").toLowerCase().replace(/[\s._-]/g, "");

export function serverPlace(server: Server): ServerPlace | null {
  const country = server.country?.toUpperCase();
  for (const value of [server.city, server.region]) {
    const key = `${country}:${normalize(value || "")}`;
    if (cityPoints[key]) return { point: cityPoints[key], precision: "city" };
  }
  const point = (countryCenters as unknown as Record<string, Point>)[country];
  return point ? { point, precision: "country" } : null;
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
