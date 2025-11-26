function arcPoints(start, end, segments = 100) {
    const lat1 = start[0] * Math.PI / 180;
    const lon1 = start[1] * Math.PI / 180;
    const lat2 = end[0] * Math.PI / 180;
    const lon2 = end[1] * Math.PI / 180;

    const d = 2 * Math.asin(Math.sqrt(
        Math.sin((lat1-lat2)/2)**2 +
        Math.cos(lat1)*Math.cos(lat2)*Math.sin((lon1-lon2)/2)**2
    ));
    
    let points = [];
    for (let i = 0; i <= segments; i++) {
        const f = i / segments;
        const A = Math.sin((1 - f) * d) / Math.sin(d);
        const B = Math.sin(f * d) / Math.sin(d);

        const x = A * Math.cos(lat1) * Math.cos(lon1) + B * Math.cos(lat2) * Math.cos(lon2);
        const y = A * Math.cos(lat1) * Math.sin(lon1) + B * Math.cos(lat2) * Math.sin(lon2);
        const z = A * Math.sin(lat1) + B * Math.sin(lat2);

        points.push([
            Math.atan2(z, Math.sqrt(x*x + y*y)) * 180 / Math.PI,
            Math.atan2(y, x) * 180 / Math.PI
        ]);
    }
    return points;
}