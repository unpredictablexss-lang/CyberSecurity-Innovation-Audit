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
import "antd/dist/reset.css";
import { api, artifact, terminal } from "../api";
import { State, Hash, go, CodeView, Header, labels } from "../components";
const { Text, Title, Paragraph } = Typography;
export default function Cases() {
  const [cases, setCases] = useState<any[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    api("/cases")
      .then(setCases)
      .catch((e) => setError(String(e)));
  }, []);
  return (
    <>
      <Header
        title="调查案例"
        description="人工关联根因，保留逐条依据。案例、候选与确认漏洞分别计数。"
      />
      {error && <Alert type="error" message={error} />}
      <Card>
        <Table<any>
          rowKey="id"
          dataSource={cases}
          columns={[
            { title: "案例", dataIndex: "title" },
            { title: "状态", render: () => <Tag>调查中 · 未确认</Tag> },
            { title: "关联观测", render: (_: any, c: any) => c.links.length },
            {
              title: "创建时间",
              dataIndex: "created_at",
              render: (x: string) => new Date(x).toLocaleString(),
            },
          ]}
          expandable={{
            expandedRowRender: (c) => (
              <>
                {c.links.map((l: any) => (
                  <div className="obligation" key={l.job_id + l.candidate_id}>
                    <a onClick={() => go("/tasks/" + l.job_id)}>
                      来源任务 {l.job_id.slice(0, 12)}
                    </a>
                    <Paragraph>{l.rationale}</Paragraph>
                    <Text code>{l.candidate_id}</Text>
                  </div>
                ))}
              </>
            ),
          }}
          locale={{ emptyText: "从任务候选列表选择观测并建立案例。" }}
        />
      </Card>
    </>
  );
}
