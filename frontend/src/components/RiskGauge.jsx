import React from 'react';

export default function RiskGauge({ score = 0 }) {
  const normalizedScore = Math.min(Math.max(score, 0), 100);
  
  // Calculate stroke dashoffset for radial gauge
  const radius = 60;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (normalizedScore / 100) * circumference * 0.75;

  const getColor = (s) => {
    if (s >= 75) return '#FF0055'; // Red
    if (s >= 50) return '#F59E0B'; // Amber
    if (s >= 25) return '#00F0FF'; // Cyan
    return '#00FF9D'; // Neon Green
  };

  const getRiskLabel = (s) => {
    if (s >= 75) return 'CRITICAL RISK';
    if (s >= 50) return 'HIGH RISK';
    if (s >= 25) return 'MODERATE RISK';
    if (s > 0) return 'LOW RISK';
    return 'CLEAN';
  };

  const color = getColor(normalizedScore);

  return (
    <div className="flex flex-col items-center justify-center p-3 relative">
      <div className="relative w-36 h-36 flex items-center justify-center">
        <svg className="w-full h-full -rotate-135" viewBox="0 0 160 160">
          {/* Background Track */}
          <circle
            cx="80"
            cy="80"
            r={radius}
            stroke="#1E293B"
            strokeWidth="12"
            fill="transparent"
            strokeDasharray={circumference * 0.75}
            strokeDashoffset="0"
            strokeLinecap="round"
          />
          {/* Active Risk Track */}
          <circle
            cx="80"
            cy="80"
            r={radius}
            stroke={color}
            strokeWidth="12"
            fill="transparent"
            strokeDasharray={circumference * 0.75}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-700 ease-out"
          />
        </svg>

        {/* Center Score Display */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-extrabold font-mono text-white tracking-tight" style={{ color }}>
            {normalizedScore}
          </span>
          <span className="text-[10px] font-mono text-slate-400">/ 100</span>
        </div>
      </div>

      <div className="mt-1 px-2.5 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider" style={{ color, backgroundColor: `${color}15`, border: `1px solid ${color}40` }}>
        {getRiskLabel(normalizedScore)}
      </div>
    </div>
  );
}
