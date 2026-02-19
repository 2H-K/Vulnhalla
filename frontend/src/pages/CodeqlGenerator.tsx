import { useState } from 'react';
import {
  Typography,
  Card,
  Row,
  Col,
  Button,
  Form,
  Input,
  Select,
  Space,
  Tag,
  Divider,
  Alert,
  message,
  Spin,
  Result,
  Tabs,
  List,
  Badge,
  Checkbox,
  Switch,
  Tooltip,
  Modal,
  Empty,
} from 'antd';
import {
  CodeOutlined,
  RobotOutlined,
  PlayCircleOutlined,
  CopyOutlined,
  SaveOutlined,
  FileTextOutlined,
  ThunderboltOutlined,
  SafetyOutlined,
  InfoCircleOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  HistoryOutlined,
  DeleteOutlined,
} from '@ant-design/icons';
import type { ProgrammingLanguage, CodeqlGenerationForm } from '../types';
import { COMMON_VULNERABILITIES, LANGUAGE_LABELS } from '../types';
import '../styles/Page.css';

const { Title, Paragraph, Text } = Typography;
const { Option } = Select;
const { TextArea } = Input;
const { Search } = Input;

// 模拟生成历史
const mockHistory = [
  {
    id: '1',
    description: '检测 Java 中的 SQL 注入漏洞',
    language: 'java',
    targetVulnerability: 'CWE-89',
    status: 'completed',
    createdAt: '2026-02-18 14:30:22',
  },
  {
    id: '2',
    description: '检测 JavaScript 中的 XSS 漏洞',
    language: 'javascript',
    targetVulnerability: 'CWE-79',
    status: 'completed',
    createdAt: '2026-02-17 10:15:45',
  },
  {
    id: '3',
    description: '检测 C++ 中的缓冲区溢出',
    language: 'cpp',
    targetVulnerability: 'CWE-119',
    status: 'failed',
    createdAt: '2026-02-16 16:20:33',
  },
];

const languageOptions = [
  { value: 'java', label: 'Java' },
  { value: 'cpp', label: 'C/C++' },
  { value: 'javascript', label: 'JavaScript/TypeScript' },
  { value: 'csharp', label: 'C#' },
  { value: 'python', label: 'Python' },
  { value: 'go', label: 'Go' },
];

// 按类别分组的漏洞类型
const vulnerabilityCategories = [
  {
    name: '注入类',
    key: 'injection',
    items: COMMON_VULNERABILITIES.filter(v => v.category === 'injection'),
  },
  {
    name: 'Web安全',
    key: 'web',
    items: COMMON_VULNERABILITIES.filter(v => v.category === 'web'),
  },
  {
    name: '内存安全',
    key: 'memory',
    items: COMMON_VULNERABILITIES.filter(v => v.category === 'memory'),
  },
  {
    name: '文件处理',
    key: 'file',
    items: COMMON_VULNERABILITIES.filter(v => v.category === 'file'),
  },
  {
    name: '认证授权',
    key: 'auth',
    items: COMMON_VULNERABILITIES.filter(v => v.category === 'auth'),
  },
  {
    name: '加密安全',
    key: 'crypto',
    items: COMMON_VULNERABILITIES.filter(v => v.category === 'crypto'),
  },
  {
    name: '其他',
    key: 'other',
    items: COMMON_VULNERABILITIES.filter(v => 
      !['injection', 'web', 'memory', 'file', 'auth', 'crypto'].includes(v.category)
    ),
  },
];

// 模拟生成的 CodeQL 查询
const mockGeneratedQuery = `/**
 * CodeQL 查询：检测 SQL 注入漏洞
 * 由 LLM 自动生成
 * 目标：CWE-89 SQL Injection
 */
 
import java
import semmle.code.java.dataflow.DataFlow

/**
 * SQL 注入污点配置
 */
class SqlInjectionTaintTracking extends TaintTracking::Configuration {
  SqlInjectionTaintTracking() { this = "SqlInjectionTaintTracking" }
  
  override predicate isSource(DataFlow::Node source) {
    exists(Variable v | v.getAnAssignedValue() = source.asExpr())
  }
  
  override predicate isSink(DataFlow::Node sink) {
    exists(MethodCall call |
      call.getMethod().getName() = "execute" or
      call.getMethod().getName() = "executeQuery" or
      call.getMethod().getName() = "createStatement"
    |
      sink.asExpr() = call.getAnArgument()
    )
  }
}

/**
 * 检测可能存在 SQL 注入的代码
 */
from SqlInjectionTaintTracking cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select sink, "Potential SQL injection vulnerability detected"
`;

const CodeqlGenerator = () => {
  const [activeTab, setActiveTab] = useState<string>('generate');
  const [form] = Form.useForm();
  const [generating, setGenerating] = useState(false);
  const [generatedCode, setGeneratedCode] = useState<string | null>(null);
  const [selectedVulnerability, setSelectedVulnerability] = useState<string>('');
  const [customDescription, setCustomDescription] = useState<string>('');

  // 处理生成
  const handleGenerate = async (values: CodeqlGenerationForm) => {
    setGenerating(true);
    setGeneratedCode(null);

    // 模拟 LLM 生成过程
    setTimeout(() => {
      setGenerating(false);
      setGeneratedCode(mockGeneratedQuery);
      message.success('CodeQL 查询生成成功！');
    }, 3000);
  };

  // 复制到剪贴板
  const handleCopy = () => {
    if (generatedCode) {
      navigator.clipboard.writeText(generatedCode);
      message.success('已复制到剪贴板');
    }
  };

  // 保存查询
  const handleSave = () => {
    message.success('查询已保存到自定义包');
  };

  // Tab 内容
  const tabItems = [
    {
      key: 'generate',
      label: (
        <span>
          <RobotOutlined /> 生成查询
        </span>
      ),
      children: (
        <Row gutter={[24, 24]}>
          {/* 左侧：配置表单 */}
          <Col xs={24} lg={12}>
            <Card title="生成配置">
              <Form
                form={form}
                layout="vertical"
                onFinish={handleGenerate}
                initialValues={{
                  language: 'java',
                  includeExamples: true,
                  strictMode: false,
                }}
              >
                {/* 语言选择 */}
                <Form.Item
                  name="language"
                  label="编程语言"
                  rules={[{ required: true, message: '请选择编程语言' }]}
                >
                  <Select placeholder="选择要生成查询的语言">
                    {languageOptions.map(lang => (
                      <Option key={lang.value} value={lang.value}>
                        {lang.label}
                      </Option>
                    ))}
                  </Select>
                </Form.Item>

                <Divider>目标漏洞类型</Divider>

                {/* 快速选择常用漏洞 */}
                <Form.Item
                  name="vulnerabilityType"
                  label="选择漏洞类型"
                  tooltip="从常用漏洞类型中选择"
                >
                  <Select
                    placeholder="选择漏洞类型"
                    onChange={(value) => {
                      setSelectedVulnerability(value);
                      setCustomDescription('');
                    }}
                    allowClear
                  >
                    {vulnerabilityCategories.map(cat => (
                      <Option key={cat.key} disabled>
                        <div style={{ fontWeight: 600, color: '#666' }}>{cat.name}</div>
                      </Option>
                    ))}
                    {vulnerabilityCategories.flatMap(cat =>
                      cat.items.map(vuln => (
                        <Option key={vuln.cwe} value={vuln.cwe}>
                          <Tag color="red">{vuln.cwe}</Tag> {vuln.name}
                        </Option>
                      ))
                    )}
                  </Select>
                </Form.Item>

                <Divider>或</Divider>

                {/* 自定义描述 */}
                <Form.Item
                  name="customDescription"
                  label="自定义描述"
                  tooltip="用自然语言描述您想要检测的漏洞"
                  extra="例如：检测可能导致任意命令执行的路径遍历漏洞"
                >
                  <TextArea
                    rows={3}
                    placeholder="用自然语言描述要检测的漏洞..."
                    onChange={(e) => {
                      setCustomDescription(e.target.value);
                      if (e.target.value) {
                        setSelectedVulnerability('');
                      }
                    }}
                  />
                </Form.Item>

                <Divider>生成选项</Divider>

                {/* 选项 */}
                <Form.Item
                  name="includeExamples"
                  valuePropName="checked"
                >
                  <Space>
                    <Switch checkedChildren="开" unCheckedChildren="关" />
                    <span>包含代码示例</span>
                    <Tooltip title="在查询中添加常见的漏洞代码示例作为参考">
                      <InfoCircleOutlined style={{ color: '#999' }} />
                    </Tooltip>
                  </Space>
                </Form.Item>

                <Form.Item
                  name="strictMode"
                  valuePropName="checked"
                >
                  <Space>
                    <Switch checkedChildren="开" unCheckedChildren="关" />
                    <span>严格模式</span>
                    <Tooltip title="启用更严格的检测规则，减少误报但可能增加漏报">
                      <InfoCircleOutlined style={{ color: '#999' }} />
                    </Tooltip>
                  </Space>
                </Form.Item>

                {/* 生成按钮 */}
                <Form.Item>
                  <Button
                    type="primary"
                    htmlType="submit"
                    icon={<RobotOutlined />}
                    loading={generating}
                    size="large"
                    block
                    disabled={!selectedVulnerability && !customDescription}
                  >
                    {generating ? '正在生成...' : '生成 CodeQL 查询'}
                  </Button>
                </Form.Item>

                <Alert
                  message="说明"
                  description="LLM 将根据您选择的漏洞类型或描述生成对应的 CodeQL 查询。生成的查询基于官方最佳实践和安全研究。"
                  type="info"
                  showIcon
                />
              </Form>
            </Card>
          </Col>

          {/* 右侧：生成结果 */}
          <Col xs={24} lg={12}>
            <Card
              title={
                <Space>
                  <CodeOutlined />
                  <span>生成的查询</span>
                </Space>
              }
              extra={
                generatedCode && (
                  <Space>
                    <Button icon={<CopyOutlined />} onClick={handleCopy}>
                      复制
                    </Button>
                    <Button type="primary" icon={<SaveOutlined />} onClick={handleSave}>
                      保存
                    </Button>
                  </Space>
                )
              }
              style={{ height: '100%' }}
            >
              {generating ? (
                <div style={{ textAlign: 'center', padding: '60px 0' }}>
                  <Spin size="large" />
                  <div style={{ marginTop: 16 }}>
                    <Text>正在使用 LLM 生成 CodeQL 查询...</Text>
                    <br />
                    <Text type="secondary">这可能需要几秒钟时间</Text>
                  </div>
                </div>
              ) : generatedCode ? (
                <pre
                  style={{
                    background: '#f5f5f5',
                    padding: 16,
                    borderRadius: 6,
                    maxHeight: 500,
                    overflow: 'auto',
                    fontSize: 12,
                    fontFamily: 'Consolas, Monaco, monospace',
                  }}
                >
                  {generatedCode}
                </pre>
              ) : (
                <Empty
                  image={Empty.PRESENTED_IMAGE_SIMPLE}
                  description={
                    <span>
                      点击"生成 CodeQL 查询"按钮开始生成
                    </span>
                  }
                />
              )}
            </Card>
          </Col>
        </Row>
      ),
    },
    {
      key: 'history',
      label: (
        <span>
          <HistoryOutlined /> 生成历史
        </span>
      ),
      children: (
        <Card>
          <List
            itemLayout="horizontal"
            dataSource={mockHistory}
            renderItem={(item) => (
              <List.Item
                actions={[
                  <Tooltip title="重新生成">
                    <Button type="text" icon={<PlayCircleOutlined />} />
                  </Tooltip>,
                  <Tooltip title="删除">
                    <Button type="text" danger icon={<DeleteOutlined />} />
                  </Tooltip>,
                ]}
              >
                <List.Item.Meta
                  avatar={
                    <Badge
                      status={item.status === 'completed' ? 'success' : 'error'}
                    />
                  }
                  title={
                    <Space>
                      <Text strong>{item.description}</Text>
                      <Tag>{LANGUAGE_LABELS[item.language as ProgrammingLanguage]}</Tag>
                      <Tag color="red">{item.targetVulnerability}</Tag>
                    </Space>
                  }
                  description={
                    <Space>
                      <Text type="secondary">{item.createdAt}</Text>
                      {item.status === 'completed' ? (
                        <Tag icon={<CheckCircleOutlined />} color="success">
                          生成成功
                        </Tag>
                      ) : (
                        <Tag icon={<CloseCircleOutlined />} color="error">
                          生成失败
                        </Tag>
                      )}
                    </Space>
                  }
                />
              </List.Item>
            )}
          />
        </Card>
      ),
    },
  ];

  return (
    <div className="generator-page">
      <div className="page-header">
        <Title level={3}>
          <Space>
            <RobotOutlined />
            LLM 生成 CodeQL 查询
          </Space>
        </Title>
        <Paragraph type="secondary">
          使用人工智能自动生成 CodeQL 安全检测查询，无需编写代码
        </Paragraph>
      </div>

      {/* 功能说明 */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} md={8}>
          <Card size="small">
            <Space>
              <ThunderboltOutlined style={{ fontSize: 24, color: '#1890ff' }} />
              <div>
                <div style={{ fontWeight: 500 }}>快速生成</div>
                <div style={{ fontSize: 12, color: '#666' }}>选择漏洞类型即可自动生成</div>
              </div>
            </Space>
          </Card>
        </Col>
        <Col xs={24} md={8}>
          <Card size="small">
            <Space>
              <SafetyOutlined style={{ fontSize: 24, color: '#52c41a' }} />
              <div>
                <div style={{ fontWeight: 500 }}>安全可靠</div>
                <div style={{ fontSize: 12, color: '#666' }}>基于官方最佳实践生成</div>
              </div>
            </Space>
          </Card>
        </Col>
        <Col xs={24} md={8}>
          <Card size="small">
            <Space>
              <FileTextOutlined style={{ fontSize: 24, color: '#722ed1' }} />
              <div>
                <div style={{ fontWeight: 500 }}>可自定义</div>
                <div style={{ fontSize: 12, color: '#666' }}>支持自然语言描述需求</div>
              </div>
            </Space>
          </Card>
        </Col>
      </Row>

      {/* 主要内容 */}
      <Tabs
        activeKey={activeTab}
        onChange={setActiveTab}
        items={tabItems}
      />
    </div>
  );
};

export default CodeqlGenerator;
