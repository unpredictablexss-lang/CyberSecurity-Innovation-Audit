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
export default function Capabilities({ detectors, embedded = false }: { detectors: any[]; embedded?: boolean }) {
  return (
    <>
      {!embedded && <Header
        title="能力与研发状态"
        description="区分已接入的操作、运行条件与仍未验证的安全结论。"
      />}
      <Row gutter={20}>
        <Col span={14}>
          <Card title="已接入检测器">
            {detectors.map((d) => (
              <div className="obligation" key={d.id}>
                <Text strong>{d.id}</Text>
                <Tag>{d.version}</Tag>
                <Paragraph>{d.summary}</Paragraph>
                <Tag color="blue">candidate / unassessed</Tag>
              </div>
            ))}
          </Card>
        </Col>
        <Col span={10}>
          <Card title="平台模块状态">
            <Timeline
              items={[
                {
                  color: "blue",
                  children:
                    "只读调查：固定源码摘录、证据义务、Git 历史与有限符号事实已接入；不调用模型、不执行任意命令、不升级结论。",
                },
                {
                  color: "orange",
                  children:
                    "动态验证：AUTH-01 已接入固定 Docker Harness 与独立 Worker；缺少 Docker daemon 或固定镜像时返回 blocked。A 线 PoC 尚未接入此 Worker。",
                },
                {
                  color: "blue",
                  children:
                    "源码同步、双 SHA / 日期区间与版本矩阵已接入；输出候选观察差异，affected / fixed / not_present 仍需证据，当前为 unknown。",
                },
              ]}
            />
          </Card>
          <Alert
            type="info"
            className="section-gap"
            message="平台入口已接通，证据闭环仍在建设"
            description="当前环境 Docker CLI 不可用，隔离验证无法在此重跑；组件 Harness 历史通过记录不代表产品入口可达或漏洞已确认。"
          />
        </Col>
      </Row>
    </>
  );
}
