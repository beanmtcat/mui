Globe data is bundled locally; the page makes no map tile or geocoding requests.

- `world-110m.json` is a reduced copy of Natural Earth's public-domain
  1:110m Admin 0 countries GeoJSON from
  https://github.com/nvkelso/natural-earth-vector (coordinates rounded to
  0.01 degrees, non-display properties removed).
- `country-centers.json` combines Natural Earth label points with bounding-box
  centers from https://github.com/samayo/country-json (MIT license in
  `COUNTRY_JSON_LICENSE`). A few small territories absent from 1:110m data
  have manually placed markers.

These approximate points place a server by country when its city is not in the
small built-in city list. They are not a server's measured network location.
