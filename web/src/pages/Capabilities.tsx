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
export default function Capabilities({ detectors }: { detectors: any[] }) {
  return (
    <>
      <Header
        title="能力与研发状态"
        description="只展示已实现能力，未接入模块不模拟成功。"
      />
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
          <Card title="后续模块">
            <Timeline
              items={[
                {
                  color: "gray",
                  children: "Agent 调查：待实现。当前不发送源码到模型服务。",
                },
                {
                  color: "gray",
                  children: "动态验证：待接入已审查 Harness 与独立隔离环境。",
                },
                {
                  color: "gray",
                  children: "版本影响与修复重验：待实现。告警消失不代表修复。",
                },
              ]}
            />
          </Card>
          <Alert
            type="info"
            className="section-gap"
            message="当前支持快照审计与人工调查"
            description="队友的新算法和验证模块继续独立审查接入。"
          />
        </Col>
      </Row>
    </>
  );
}
