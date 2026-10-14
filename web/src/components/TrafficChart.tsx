import { memo, useState } from "react";
import { bytes } from "../api";

export type TrafficPoint = { at: string; uplink: number; downlink: number };

function trafficTime(at: string) {
  return new Date(at).toLocaleString("zh-CN", {
    month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

function trafficAxisBytes(value: number) {
  return value < 1024 && value % 1 !== 0 ? `${value.toFixed(1)} B` : bytes(value);
}

// Hand-drawn SVG line chart (no chart library). Memoized: re-renders only when
// the point list identity changes.
function TrafficChart({ points }: { points: TrafficPoint[] }) {
  const [hoverIndex, setHoverIndex] = useState<number | null>(null);
  const width = 720;
  const height = 200;
  const peak = Math.max(0, ...points.flatMap((p) => [p.uplink, p.downlink]));
  const magnitude = peak > 0 ? 10 ** Math.floor(Math.log10(peak)) : 1;
  const ceiling = peak > 0
    ? ([1, 2, 5, 10].find((step) => step * magnitude >= peak) || 10) * magnitude
    : 1;
  const x = (index: number) => 6 + (index / Math.max(1, points.length - 1)) * (width - 12);
  const y = (value: number) => height - 6 - (value / ceiling) * (height - 12);
  const path = (key: "uplink" | "downlink") =>
    points.map((point, index) => `${index ? "L" : "M"}${x(index).toFixed(1)},${y(point[key]).toFixed(1)}`).join(" ");
  const selectedIndex = hoverIndex === null ? points.length - 1 : Math.min(hoverIndex, points.length - 1);
  const selected = points[selectedIndex];
  const ticks = [0, 6, 12, 18, points.length - 1].filter((index, position, all) =>
    index < points.length && all.indexOf(index) === position,
  );

  return (
    <div className="trafficChart">
      <div className="trafficChartHead">
        <p className="hint">近 24 小时，按小时汇总</p>
        <div className="trafficLegend"><span className="up">上行</span><span className="down">下行</span></div>
      </div>
      <div className="trafficPlotRow">
        <div className="trafficYAxis">
          <span>{peak ? trafficAxisBytes(ceiling) : ""}</span>
          <span>{peak > 1 ? trafficAxisBytes(ceiling / 2) : ""}</span>
          <span>0 B</span>
        </div>
        <div className="trafficPlot">
          <svg
            viewBox={`0 0 ${width} ${height}`}
            preserveAspectRatio="none"
            role="img"
            aria-label="近 24 小时节点流量折线图，上行和下行分别显示"
            onMouseMove={(event) => {
              const bounds = event.currentTarget.getBoundingClientRect();
              const ratio = (event.clientX - bounds.left) / bounds.width;
              setHoverIndex(Math.max(0, Math.min(points.length - 1, Math.round(ratio * (points.length - 1)))));
            }}
            onMouseLeave={() => setHoverIndex(null)}
          >
            {[6, height / 2, height - 6].map((at) => <line key={at} className="trafficGridLine" x1="0" x2={width} y1={at} y2={at} />)}
            <path className="trafficLine up" d={path("uplink")} />
            <path className="trafficLine down" d={path("downlink")} />
            {hoverIndex !== null && selected && (
              <>
                <line className="trafficCursor" x1={x(selectedIndex)} x2={x(selectedIndex)} y1="6" y2={height - 6} />
                <circle className="trafficDot up" cx={x(selectedIndex)} cy={y(selected.uplink)} r="5" />
                <circle className="trafficDot down" cx={x(selectedIndex)} cy={y(selected.downlink)} r="5" />
              </>
            )}
          </svg>
          {peak === 0 && <div className="trafficZero">近 24 小时流量为 0</div>}
        </div>
      </div>
      <div className="trafficXAxis">
        {ticks.map((index, position) => <span className={position === 1 || position === 3 ? "optional" : ""} key={index}>{trafficTime(points[index].at)}</span>)}
      </div>
      {selected && (
        <div className="trafficReadout">
          <strong>{trafficTime(selected.at)}</strong>
          <span>↑ {bytes(selected.uplink)}</span>
          <span>↓ {bytes(selected.downlink)}</span>
        </div>
      )}
      <details className="trafficDetails">
        <summary>查看逐小时数据</summary>
        <div className="trafficDetailTable">
          {[...points].reverse().map((point) => (
            <div key={point.at}><time dateTime={point.at}>{trafficTime(point.at)}</time><span>↑ {bytes(point.uplink)}</span><span>↓ {bytes(point.downlink)}</span></div>
          ))}
        </div>
      </details>
    </div>
  );
}

export default memo(TrafficChart);
