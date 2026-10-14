import React, { memo } from "react";
import qrcode from "qrcode-generator";

// Drawn as inline SVG rectangles (no <img>, no third-party requests), so it
// works under the page CSP (script-src 'self', img-src 'self' data:).
function QRCode({ text }: { text: string }) {
  const code = qrcode(0, "M");
  code.addData(text);
  code.make();
  const size = code.getModuleCount();
  const cells: React.ReactNode[] = [];
  for (let row = 0; row < size; row++)
    for (let col = 0; col < size; col++)
      if (code.isDark(row, col)) cells.push(<rect key={row + "-" + col} x={col} y={row} width="1" height="1" />);
  return (
    <svg className="qrCode" viewBox={`-2 -2 ${size + 4} ${size + 4}`} role="img" aria-label="TOTP 二维码" shapeRendering="crispEdges">
      <rect x="-2" y="-2" width={size + 4} height={size + 4} fill="#fff" />
      <g fill="#000">{cells}</g>
    </svg>
  );
}

export default memo(QRCode);
