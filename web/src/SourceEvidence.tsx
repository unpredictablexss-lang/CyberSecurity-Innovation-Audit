import React from "react";
import {
  Alert,
  Card,
  Form,
  Input,
  InputNumber,
  Row,
  Col,
  Button,
  Typography,
  message,
} from "antd";
import { api } from "./api";
const { Text, Paragraph } = Typography;
export default function SourceEvidence({
  jobId,
  detail,
  reload,
}: {
  jobId: string;
  detail: any;
  reload: () => Promise<void>;
}) {
  const [form] = Form.useForm();
  return (
    <Card className="section-gap" title="补充固定源码证据">
      <Alert
        type="info"
        message="源码摘录由服务器按本次 commit 校验"
        description="摘录证明内容与位置；复核人的解释仍需审查，不自动证明支配性、可达性或漏洞成立。"
      />
      {(detail.supplemental_evidence || []).map((e: any) => (
        <div className="obligation" key={e.id}>
          <Text strong>
            {e.file}:{e.start_line}-{e.end_line}
          </Text>
          <Paragraph>{e.note}</Paragraph>
          <Text code copyable>
            {e.id}
          </Text>
          <pre className="raw">{e.text}</pre>
          <Text type="secondary">摘录 SHA-256：{e.excerpt_sha256}</Text>
        </div>
      ))}
      <Form
        className="section-gap"
        form={form}
        layout="vertical"
        initialValues={{
          file: detail.file,
          start_line: detail.line,
          end_line: detail.line,
        }}
        onFinish={async (values) => {
          try {
            await api(
              "/scans/" + jobId + "/findings/" + detail.id + "/evidence",
              values,
            );
            form.setFieldValue("note", "");
            await reload();
            message.success("已保存固定来源的源码证据");
          } catch (e) {
            message.error(String(e));
          }
        }}
      >
        <Form.Item
          name="file"
          label="本次扫描内的源码路径"
          rules={[{ required: true }]}
        >
          <Input />
        </Form.Item>
        <Row gutter={16}>
          <Col span={12}>
            <Form.Item
              name="start_line"
              label="起始行"
              rules={[{ required: true }]}
            >
              <InputNumber min={1} />
            </Form.Item>
          </Col>
          <Col span={12}>
            <Form.Item
              name="end_line"
              label="结束行（最多 100 行）"
              rules={[{ required: true }]}
            >
              <InputNumber min={1} />
            </Form.Item>
          </Col>
        </Row>
        <Form.Item
          name="note"
          label="证据用途与解释限制"
          rules={[{ required: true }]}
        >
          <Input.TextArea rows={3} maxLength={4000} />
        </Form.Item>
        <Button htmlType="submit">保存源码证据</Button>
      </Form>
    </Card>
  );
}
