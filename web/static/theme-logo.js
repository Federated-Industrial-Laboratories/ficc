// SPDX-License-Identifier: Apache-2.0
// Render theme logos from fixed geometry or validated paths without SVG markup.
const NS = 'http://www.w3.org/2000/svg';
function svgNode(tag, attributes) {
  const node = document.createElementNS(NS, tag);
  for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, String(value));
  return node;
}
export function themeLogo(theme, flat = false) {
  const { logo, colors } = theme, paint = value => colors[value] ?? value;
  const svg = svgNode('svg', { viewBox: (logo.viewBox ?? [0, 0, 80, 80]).join(' '),
    width: 64, height: 64, 'aria-hidden': 'true', focusable: 'false', class: 'theme-logo' });
  const primary = paint(logo.color), secondary = paint(logo.secondary);
  function path(d, fill = primary, stroke = 'none', width = 1) {
    svg.append(svgNode('path', { d, fill, stroke, 'stroke-width': width, 'stroke-linejoin': 'round' }));
  }
  if (logo.type === 'paths') {
    for (const item of logo.paths) path(item.d, paint(item.fill), paint(item.stroke), item.strokeWidth);
  } else if (logo.type === 'monogram') {
    path('M8 8H72V72H8Z', 'none', secondary, 3);
    path('M20 20H46V29H30V36H43V45H30V60H20Z');
    path('M51 20H60V60H51Z', secondary);
  } else if (logo.type === 'orbit') {
    path('M40 7 70 24V56L40 73 10 56V24Z', 'none', secondary, 3);
    path('M40 7V73M10 24 70 56M70 24 10 56', 'none', secondary, 2);
    path('M40 26 53 33V47L40 54 27 47V33Z');
  } else {
    path('M23 51 40 62 58 51M40 62V35', 'none', secondary, 4);
    for (const [x, y, accent] of [[28, 10, false], [7, 40, true], [45, 41, false]]) {
      const fill = accent ? primary : colors.surface;
      path(`M${x} ${y}l17-7 16 9-17 8Z`, flat ? fill : colors.highlight, secondary);
      path(`M${x} ${y}l16 10v23l-16-10Z`, fill, secondary);
      path(`M${x + 16} ${y + 10}l17-8v23l-17 8Z`, accent ? primary : secondary, secondary);
      path(`M${x + 4} ${y + 8}l8 5m-8 2 8 5m-8 2 8 5`, 'none', accent ? colors['on-accent'] : colors.ink, 1.2);
    }
  }
  return svg;
}
