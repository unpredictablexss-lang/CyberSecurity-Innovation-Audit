import React, { useEffect, useState } from "react";
import {
  Alert,
  Button,
  Card,
  Col,
  Form,
  Input,
  Modal,
  Popconfirm,
  Row,
  Space,
  Table,
  Tag,
  Typography,
  message,
} from "antd";
import { api, apiDelete } from "../api";
import { Hash, Header } from "../components";
import { canUseCatalog, canUseVerifiedRepository, filterManagedRepositories } from "../features/workbench/repositoryState.js";
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
  const [rootForm] = Form.useForm();
  const [error, setError] = useState("");
  const [rootError, setRootError] = useState("");
  const [refs, setRefs] = useState<any[] | null>(null);
  const [catalog, setCatalog] = useState<any[]>([]);
  const [managedRepos, setManagedRepos] = useState<any[]>([]);
  const [rootCatalog, setRootCatalog] = useState<any[]>([]);
  const [catalogLoading, setCatalogLoading] = useState(true);
  const [catalogError, setCatalogError] = useState("");
  const [discovery, setDiscovery] = useState<any>(null);
  const [discoveryBusy, setDiscoveryBusy] = useState<number | null>(null);
  const [registering, setRegistering] = useState(false);
  const [addingRoot, setAddingRoot] = useState(false);
  const [removingRoot, setRemovingRoot] = useState<string | null>(null);
  const [repositorySearch, setRepositorySearch] = useState("");

  const loadCatalog = async () => {
    setCatalogLoading(true);
    setCatalogError("");
    try {
      const [result, managed, sourceRoots] = await Promise.all([
        api("/repositories/catalog"),
        api("/repositories/managed"),
        api("/repositories/roots"),
      ]);
      setCatalog(Array.isArray(result) ? result : []);
      setManagedRepos(Array.isArray(managed) ? managed : []);
      setRootCatalog(Array.isArray(sourceRoots) ? sourceRoots : []);
    } catch (reason) {
      setCatalogError(String(reason));
    } finally {
      setCatalogLoading(false);
    }
  };
  useEffect(() => { void loadCatalog(); }, []);

  const catalogById = new Map(catalog.map((item) => [item.id, item]));
  const visibleRepositories = filterManagedRepositories(managedRepos, catalog, repositorySearch);
  const rootRows = rootCatalog.length ? rootCatalog.map((root: any) => ({
    key: root.id, id: root.id, index: root.index, path: root.path, label: root.alias,
    count: root.repository_count, status: root.status, managed: root.managed,
  })) : roots.map((path, index) => {
    const normalized = String(path).replace(/\/+$/, "");
    const count = repos.filter((repo) => String(repo.path || "").startsWith(normalized + "/")).length;
    return { key: index, index, path, label: "源码根目录 " + (index + 1) + " · " + (normalized.split("/").pop() || normalized), count, status: "unknown", managed: false };
  });
  const discover = async (rootId: string) => {
    setDiscoveryBusy(rootRows.find((root: any) => root.id === rootId)?.index ?? null);
    setDiscovery(null);
    setRootError("");
    try {
      const result = await api("/repositories/discover?root_id=" + encodeURIComponent(rootId));
      setDiscovery(result);
    } catch (reason) {
      setRootError(String(reason));
    } finally {
      setDiscoveryBusy(null);
    }
  };
  const addRoot = async (values: { alias?: string; path: string }) => {
    setAddingRoot(true);
    setRootError("");
    try {
      await api("/repositories/roots", values);
      rootForm.resetFields();
      await loadCatalog();
      await refresh();
      message.success("受控源码根目录已添加；可立即发现并登记其中的 Git 仓库");
    } catch (reason) {
      setRootError(String(reason));
    } finally {
      setAddingRoot(false);
    }
  };
  const removeRoot = async (rootId: string) => {
    setRemovingRoot(rootId);
    setRootError("");
    try {
      await apiDelete("/repositories/roots/" + encodeURIComponent(rootId));
      await loadCatalog();
      await refresh();
      message.success("源码根目录已移除；该目录下登记的仓库会变为不可用，历史任务快照保留");
    } catch (reason) {
      setRootError(String(reason));
    } finally {
      setRemovingRoot(null);
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
      <Card className="section-gap" title="受控本地源码根目录">
        <Alert type="warning" showIcon
          message="添加目录会允许 OHScanner 读取其中的本地 Git 仓库"
          description="只登记你明确授权的源码目录。服务端会拒绝符号链接路径、磁盘挂载点、工作台数据目录、组/所有人可写目录和重叠路径；仓库发现有固定深度、数量和时间预算，不执行仓库钩子或网络同步。"
        />
        {rootError && <Alert className="section-gap" type="error" showIcon message="源码管理操作失败" description={rootError} />}
        {catalogError && <Alert className="section-gap" type="error" showIcon message="读取仓库与源码根目录失败" description={catalogError} />}
        <Table className="section-gap" size="small" pagination={false} rowKey="key" dataSource={rootRows}
          loading={catalogLoading}
          locale={{ emptyText: catalogLoading ? "正在读取服务端已批准的源码根目录…" : catalogError ? "读取失败，请检查上方错误信息后重试" : "服务端尚未配置可用源码根目录" }}
          columns={[
            { title: "根目录别名", dataIndex: "label" },
            { title: "服务端路径", dataIndex: "path", render: (value) => <Text code>{value}</Text> },
            { title: "状态", dataIndex: "status", render: (value) => value === "available" ? <Tag color="green">可用</Tag> : value === "unavailable" ? <Tag color="red">不可用</Tag> : <Tag>未知</Tag> },
            { title: "已登记仓库", dataIndex: "count" },
            { title: "最近校验", dataIndex: "last_checked_at", render: (value) => value ? new Date(value).toLocaleString() : "部署配置" },
            { title: "操作", render: (_: unknown, row: any) => <Space>
              <Button loading={discoveryBusy === row.index} disabled={discoveryBusy !== null || !canUseVerifiedRepository({ loading: catalogLoading, error: catalogError, status: row.status })} onClick={() => void discover(row.id)}>发现 Git 仓库</Button>
              {row.managed && <Popconfirm
                title="移除这个源码根目录？"
                description="其中登记的仓库将无法用于新审计，历史任务和快照仍保留。"
                okText="移除" cancelText="取消"
                onConfirm={() => void removeRoot(row.id)}
              ><Button danger loading={removingRoot === row.id} disabled={!canUseCatalog({ loading: catalogLoading, error: catalogError }) || removingRoot !== null}>移除</Button></Popconfirm>}
            </Space> },
          ]}
        />
        <Form className="section-gap" form={rootForm} layout="inline" onFinish={addRoot}>
          <Form.Item name="alias" label="目录别名" rules={[{ max: 80 }]}>
            <Input placeholder="例如：G盘 OpenHarmony 镜像" />
          </Form.Item>
          <Form.Item name="path" label="服务器绝对路径" rules={[{ required: true, message: "请输入服务器上的目录绝对路径" }]}>
            <Input style={{ width: 360 }} placeholder="/mnt/g/OpenHarmony-GitCode-Mirror/repos" />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={addingRoot}>校验并添加目录</Button>
        </Form>
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
            <Space className="section-gap" wrap>
              <Input.Search allowClear value={repositorySearch} onChange={(event) => setRepositorySearch(event.target.value)}
                placeholder="搜索仓库名、来源、路径或状态" style={{ width: 360, maxWidth: "100%" }} />
              <Text type="secondary">显示 {visibleRepositories.length} / {managedRepos.length} 个仓库</Text>
            </Space>
            <Table
              loading={catalogLoading}
              rowKey="id"
              dataSource={visibleRepositories}
              locale={{ emptyText: repositorySearch ? "没有匹配的仓库，请修改关键词或清空搜索。" : "尚未登记仓库" }}
              columns={[
                { title: "仓库名称", dataIndex: "id", render: (_: string, repo: any) => <Text>{catalogById.get(repo.id)?.display_name || repo.name}</Text> },
                { title: "来源根目录", render: (_: unknown, repo: any) => catalogById.get(repo.id)?.root_alias || "未知来源" },
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
                      disabled={!canUseVerifiedRepository({ loading: catalogLoading, error: catalogError, status: catalogById.get(repo.id)?.status })}
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
                  setDiscovery(null);
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
