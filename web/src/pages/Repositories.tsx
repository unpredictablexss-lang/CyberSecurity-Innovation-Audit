import React, { useEffect, useState } from "react";
import {
  Alert,
  Button,
  Card,
  Col,
  Form,
  Input,
  Modal,
  Row,
  Space,
  Table,
  Tag,
  Typography,
  message,
} from "antd";
import { api } from "../api";
import { Hash, Header } from "../components";
const { Text } = Typography;

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
  const [catalog, setCatalog] = useState<any[]>([]);
  const [catalogLoading, setCatalogLoading] = useState(true);
  const [catalogError, setCatalogError] = useState("");
  const [discovery, setDiscovery] = useState<any>(null);
  const [discoveryBusy, setDiscoveryBusy] = useState<number | null>(null);
  const [registering, setRegistering] = useState(false);

  const loadCatalog = async () => {
    setCatalogLoading(true);
    setCatalogError("");
    try {
      const result = await api("/repositories/catalog");
      setCatalog(Array.isArray(result) ? result : []);
    } catch (reason) {
      setCatalogError(String(reason));
    } finally {
      setCatalogLoading(false);
    }
  };
  useEffect(() => { void loadCatalog(); }, []);

  const catalogById = new Map(catalog.map((item) => [item.id, item]));
  const rootRows = roots.map((path, index) => {
    const normalized = String(path).replace(/\/+$/, "");
    const count = repos.filter((repo) => String(repo.path || "").startsWith(normalized + "/")).length;
    return { key: index, index, path, label: "源码根目录 " + (index + 1) + " · " + (normalized.split("/").pop() || normalized), count };
  });
  const discover = async (rootIndex: number) => {
    setDiscoveryBusy(rootIndex);
    setDiscovery(null);
    setError("");
    try {
      const result = await api("/repositories/discover?root_index=" + rootIndex);
      setDiscovery(result);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setDiscoveryBusy(null);
    }
  };
  const useDiscovered = (item: any) => {
    form.setFieldsValue({ name: item.name_guess, path: item.path });
    setError("");
    message.info("已带入登记表单；可修改显示名称，再确认登记。名称不会验证仓库官方身份。");
  };

  return (
    <>
      {!embedded && <Header
        title="仓库与源码管理"
        description="从服务端已批准的源码根目录发现仓库；审计流程只选择仓库名称。"
      />}
      <Card className="section-gap" title="已批准的本地源码根目录" extra={<Text type="secondary">服务端安全配置 · 只读</Text>}>
        <Alert type="info" showIcon
          message="网页不会自动扩大服务端目录访问范围"
          description="下表来自 OHSCANNER_TARGET_ROOTS 与本地仓库缓存。新增或移除根目录须由部署管理员修改服务端配置并重启；每次发现都会限制遍历深度、目录数、仓库数和时间预算，不跟随符号链接。"
        />
        <Table className="section-gap" size="small" pagination={false} rowKey="key" dataSource={rootRows}
          locale={{ emptyText: "服务端尚未配置可用源码根目录" }}
          columns={[
            { title: "根目录", dataIndex: "label" },
            { title: "服务器路径", dataIndex: "path", render: (value) => <Text code>{value}</Text> },
            { title: "已登记仓库", dataIndex: "count" },
            { title: "操作", render: (_, row) => <Button loading={discoveryBusy === row.index} disabled={discoveryBusy !== null} onClick={() => void discover(row.index)}>发现 Git 仓库</Button> },
          ]}
        />
      </Card>

      {discovery && <Card className="section-gap" title={"发现结果 · " + discovery.root_name}>
        <Alert type={discovery.truncated ? "warning" : "info"} showIcon
          message={discovery.repositories.length + " 个未登记且通过 Git 校验的仓库；已有登记 " + discovery.registered_count + " 个"}
          description={"遍历 " + discovery.visited_directories + " 个目录。深度上限 " + discovery.limits.max_depth + " 层、目录上限 " + discovery.limits.max_directories + "、仓库上限 " + discovery.limits.max_repositories + "、时间预算 " + discovery.limits.time_budget_seconds + " 秒。" + (discovery.truncated ? " 已触及资源上限，结果可能不完整，可缩小根目录后再次发现。" : " 远端名称不会被当作官方身份认证。")}
        />
        <Table className="section-gap" size="small" rowKey="path" dataSource={discovery.repositories}
          locale={{ emptyText: "未发现尚未登记的有效 Git 仓库" }}
          columns={[
            { title: "默认登记名称（可修改）", dataIndex: "name_guess", render: (value) => <Text>{value}</Text> },
            { title: "服务器路径", dataIndex: "path", render: (value) => <Text code>{value}</Text> },
            { title: "可解析版本数", dataIndex: "revision_count" },
            { title: "操作", render: (_, row) => <Button onClick={() => useDiscovered(row)}>带入登记表单</Button> },
          ]}
        />
      </Card>}

      <Row className="section-gap" gutter={20}>
        <Col span={16}>
          <Card title="已登记仓库与可用状态" extra={<Button onClick={() => void loadCatalog()} loading={catalogLoading}>重新核验</Button>}>
            {catalogError && <Alert className="section-gap" type="error" showIcon message="仓库状态核验失败" description={catalogError} />}
            <Table
              loading={catalogLoading}
              rowKey="id"
              dataSource={repos}
              columns={[
                { title: "仓库名称", dataIndex: "id", render: (_: string, repo: any) => <Text>{catalogById.get(repo.id)?.display_name || repo.name}</Text> },
                {
                  title: "管理员可见的服务器路径",
                  dataIndex: "path",
                  render: (value: string) => <Text code>{value}</Text>,
                },
                {
                  title: "状态",
                  render: (_: unknown, repo: any) => {
                    const item = catalogById.get(repo.id);
                    if (catalogLoading) return <Tag>核验中</Tag>;
                    if (!item || item.status !== "available") return <Space direction="vertical" size={0}><Tag color="red">不可用于审计</Tag><Text type="secondary">{item?.reason || "目录状态未知，请重新核验"}</Text></Space>;
                    return <Space><Tag color="green">可用</Tag><Text type="secondary">HEAD {String(item.head_commit || "").slice(0, 12)} 已解析</Text></Space>;
                  },
                },
                {
                  title: "操作",
                  render: (_: unknown, repo: any) => (
                    <Button
                      disabled={catalogById.get(repo.id)?.status !== "available"}
                      onClick={() =>
                        api("/repositories/" + repo.id + "/revisions")
                          .then(setRefs)
                          .catch((reason) => setError(String(reason)))
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
        <Col span={8}>
          <Card title="登记本地仓库">
            {error && <Alert className="section-gap" type="error" showIcon message={error} />}
            <Form
              name="repository-registration"
              form={form}
              layout="vertical"
              onFinish={async (values) => {
                setRegistering(true);
                setError("");
                try {
                  await api("/repositories", values);
                  form.resetFields();
                  await refresh();
                  await loadCatalog();
                  message.success("仓库已登记并重新核验");
                } catch (reason) {
                  setError(String(reason));
                } finally {
                  setRegistering(false);
                }
              }}
            >
              <Form.Item
                name="name"
                label="仓库显示名称"
                rules={[{ required: true }]}
                extra="默认使用 local/名称；它是本机标签，不代表已验证官方来源。"
              >
                <Input placeholder="local/communication_dsoftbus" />
              </Form.Item>
              <Form.Item
                name="path"
                label="服务器上的 Git 仓库绝对路径"
                rules={[{ required: true }]}
              >
                <Input placeholder="建议从上方发现结果带入" />
              </Form.Item>
              <Button type="primary" htmlType="submit" loading={registering}>
                登记并校验仓库
              </Button>
            </Form>
            <Typography.Paragraph className="section-gap" type="secondary">
              只有路径位于上方已批准根目录内且 Git 版本可读取时，仓库才会出现在审计选择器中。路径漂移、越界或无可解析版本的仓库会保持不可用；不会自动放宽目录白名单。
            </Typography.Paragraph>
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
            { title: "对象", dataIndex: "object", render: (value: string) => <Hash value={value} /> },
          ]}
        />
      </Modal>
    </>
  );
}
