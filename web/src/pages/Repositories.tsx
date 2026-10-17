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
export default function Repositories({
  repos,
  roots,
  refresh,
  embedded = false,
}: {
  repos: any[];
  roots: string[];
  refresh: () => Promise<void>;
  embedded?: boolean;
}) {
  const [form] = Form.useForm();
  const [error, setError] = useState("");
  const [refs, setRefs] = useState<any[] | null>(null);
  return (
    <>
      {!embedded && <Header
        title="仓库与版本"
        description="登记已有本地 Git 仓库；扫描固定对象，不读取未提交修改。"
      />}
      <Row gutter={20}>
        <Col span={15}>
          <Card title="已登记仓库">
            <Table
              rowKey="id"
              dataSource={repos}
              columns={[
                { title: "仓库", dataIndex: "name" },
                {
                  title: "WSL 路径",
                  dataIndex: "path",
                  render: (x: string) => <Text code>{x}</Text>,
                },
                {
                  title: "",
                  render: (_: any, r: any) => (
                    <Button
                      onClick={() =>
                        api("/repositories/" + r.id + "/revisions")
                          .then(setRefs)
                          .catch((e) => setError(String(e)))
                      }
                    >
                      查看版本
                    </Button>
                  ),
                },
              ]}
            />
          </Card>
        </Col>
        <Col span={9}>
          <Card title="登记本地仓库">
            {error && <Alert type="error" message={error} />}
            <Form
              form={form}
              layout="vertical"
              onFinish={async (values) => {
                try {
                  await api("/repositories", values);
                  form.resetFields();
                  await refresh();
                  message.success("仓库已登记");
                } catch (e) {
                  setError(String(e));
                }
              }}
            >
              <Form.Item
                name="name"
                label="仓库标识"
                rules={[{ required: true }]}
              >
                <Input placeholder="openharmony/commonlibrary_c_utils" />
              </Form.Item>
              <Form.Item
                name="path"
                label="WSL 仓库绝对路径"
                rules={[{ required: true }]}
              >
                <Input placeholder="/home/audit/openharmony-targets/..." />
              </Form.Item>
              <Button type="primary" htmlType="submit">
                登记仓库
              </Button>
            </Form>
            <Paragraph className="section-gap" type="secondary">
              允许的父目录：
              {roots.map((x) => (
                <div key={x}>
                  <Text code>{x}</Text>
                </div>
              ))}
            </Paragraph>
          </Card>
        </Col>
      </Row>
      <Modal
        open={refs !== null}
        title="本地 Ref"
        footer={null}
        onCancel={() => setRefs(null)}
        width={800}
      >
        <Table
          rowKey="ref"
          dataSource={refs || []}
          columns={[
            { title: "Ref", dataIndex: "ref" },
            {
              title: "对象",
              dataIndex: "object",
              render: (x: string) => <Hash value={x} />,
            },
          ]}
        />
      </Modal>
    </>
  );
}
