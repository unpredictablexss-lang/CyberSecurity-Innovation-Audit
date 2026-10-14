import React, { useEffect, useRef, useState } from "react";
import {
  Alert,
  Button,
  Card,
  Checkbox,
  Col,
  ConfigProvider,
  Descriptions,
  Drawer,
  Empty,
  Form,
  Input,
  InputNumber,
  Layout,
  Menu,
  Modal,
  Row,
  Select,
  Space,
  Spin,
  Statistic,
  Table,
  Tabs,
  Tag,
  Timeline,
  Typography,
  message,
} from "antd";
import zhCN from "antd/locale/zh_CN";
import {
  AppstoreOutlined,
  BranchesOutlined,
  CodeOutlined,
  FileSearchOutlined,
  FolderOutlined,
  PlusOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  ExperimentOutlined,
} from "@ant-design/icons";
import * as monaco from "monaco-editor/esm/vs/editor/editor.api";
import "monaco-editor/esm/vs/basic-languages/cpp/cpp.contribution";
import "monaco-editor/esm/vs/basic-languages/typescript/typescript.contribution";
import "monaco-editor/esm/vs/basic-languages/javascript/javascript.contribution";
import "antd/dist/reset.css";
import { api, artifact, terminal } from "./api";
(window as any).MonacoEnvironment = {
  getWorker: () => new Worker("/assets/editor.worker.js"),
};
const { Text, Title, Paragraph } = Typography;
export const labels: Record<string, string> = {
  queued: "排队中",
  running: "运行中",
  completed: "执行完成",
  completed_with_limitations: "完成 · 存在覆盖限制",
  failed: "执行失败",
  cancelled: "已取消",
  interrupted: "执行中断",
  timed_out: "超时",
  unassessed: "待复核",
  under_review: "复核中",
  plausible_unproven: "合理怀疑 · 待补证",
  likely_false_positive: "可能误报",
  refuted: "已驳回",
  partial: "部分覆盖",
  complete: "完整覆盖",
  blocked: "受阻",
};
export function State({ value }: { value: string }) {
  return (
    <Tag
      color={
        value === "running"
          ? "processing"
          : value === "completed"
            ? "success"
            : ["failed", "timed_out"].includes(value)
              ? "error"
              : ["partial", "blocked", "completed_with_limitations"].includes(
                    value,
                  )
                ? "warning"
                : "default"
      }
    >
      {labels[value] || value}
    </Tag>
  );
}
export function Hash({ value }: { value: string }) {
  return (
    <Text className="hash" copyable={{ text: value }}>
      {value.slice(0, 12)}
    </Text>
  );
}
export function go(path: string) {
  window.location.hash = path;
}
export function useRoute() {
  const [r, set] = useState(window.location.hash.slice(1) || "/overview");
  useEffect(() => {
    const f = () => set(window.location.hash.slice(1) || "/overview");
    window.addEventListener("hashchange", f);
    return () => window.removeEventListener("hashchange", f);
  }, []);
  return r;
}
export function CodeView({ source, line = 1 }: { source: any; line?: number }) {
  const host = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!host.current) return;
    const editor = monaco.editor.create(host.current, {
      value: source.text,
      language: /\.(ts|ets)$/.test(source.file)
        ? "typescript"
        : /\.js$/.test(source.file)
          ? "javascript"
          : "cpp",
      readOnly: true,
      theme: "vs",
      automaticLayout: true,
      minimap: { enabled: false },
      fontSize: 13,
      scrollBeyondLastLine: false,
    });
    editor.createDecorationsCollection([
      {
        range: new monaco.Range(line, 1, line, 1),
        options: { isWholeLine: true, className: "candidate-line" },
      },
    ]);
    editor.revealLineInCenter(line);
    return () => {
      editor.getModel()?.dispose();
      editor.dispose();
    };
  }, [source.file, source.text, line]);
  return (
    <>
      <div className="source-meta">
        <Text strong>
          {source.file}:{line}
        </Text>
        <Space>
          Commit <Hash value={source.commit} />
          SHA-256 <Hash value={source.sha256} />
        </Space>
      </div>
      <div ref={host} className="code-editor" />
    </>
  );
}
export function Header({
  title,
  description,
  extra,
}: {
  title: string;
  description: string;
  extra?: React.ReactNode;
}) {
  return (
    <div className="page-header">
      <div>
        <div className="eyebrow">OPENHARMONY · EVIDENCE FIRST</div>
        <Title level={2}>{title}</Title>
        <Paragraph type="secondary">{description}</Paragraph>
      </div>
      {extra}
    </div>
  );
}
