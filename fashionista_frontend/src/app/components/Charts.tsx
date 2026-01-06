"use client";
import React from "react";
import { Bar } from "react-chartjs-2";
import {
  BarElement,
  CategoryScale,
  Chart as ChartJS,
  Legend,
  LinearScale,
  Title,
  Tooltip,
  ChartOptions,
  ChartData,
} from "chart.js";
ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend
);

interface BarChartProps {
  data: ChartData<"bar", number[], string>;
  options?: ChartOptions<"bar">;
}
const BarChart: React.FC<BarChartProps> = ({ data, options }) => {
  return (
    <div className="rounded-[10px] bg-[#fff] w-full h-[366px] p-4 ">
      <Bar data={data} options={options} />
    </div>
  );
};

export default BarChart;
