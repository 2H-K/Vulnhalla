import { useState } from 'react';
import {
  Typography,
  Card,
  Row,
  Col,
  Button,
  Table,
  Space,
  Tag,
  Input,
  Select,
  Form,
  Modal,
  message,
  Tooltip,
  Badge,
  Tabs,
  Statistic,
  Drawer,
  Descriptions,
  Divider,
  Alert,
} from 'antd';
import {
  SearchOutlined,
  EyeOutlined,
  FilterOutlined,
  DownloadOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  ExclamationCircleOutlined,
  SafetyOutlined,
  WarningOutlined,
  BugOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import type { Vulnerability, Severity, VulnerabilityStatus } from '../types';
import { SEVERITY_LABELS, SEVERITY_COLORS, STATUS_LABELS, CONFIDENCE_LABELS } from '../types';
import '../styles/Page.css';

const { Title, Paragraph, Text } = Typography;
const { Search } = Input;
const { Option } = Select;

// 模拟漏洞数据
const mockVulnerabilities: Vulnerability[] = [
  {
    id: 'v1',
    projectId: '1',
    projectName: 'fastbee 物联网平台',
    ruleId: 'java/sql-injection',
    ruleName: 'SQL 注入',
    severity: 'high',
    confidence: 'high',
    status: 'new',
    filePath: 'src/main/java/com/fastbee/mapper/UserMapper.java',
    startLine: 42,
    endLine: 45,
    startColumn: 5,
    endColumn: 30,
    codeSnippet: 'String sql = "SELECT * FROM users WHERE id = " + userId;',
    message: '可能存在 SQL 注入漏洞',
    description: '使用字符串拼接构建 SQL 查询可能导致 SQL 注入攻击',
    dataFlow: [],
    detectedAt: '2026-02-15 14:30:22',
    updatedAt: '2026-02-15 14:30:22',
    llmAnalysis: {
      isVulnerability: true,
      confidence: 0.85,
      reasoning: '用户输入直接拼接到 SQL 查询中，未使用参数化查询',
      suggestion: '使用预编译语句（PreparedStatement）或 ORM 框架的参数查询',
      cwe: 'CWE-89',
      owasp: 'A1',
    },
  },
  {
    id: 'v2',
    projectId: '1',
    projectName: 'fastbee 物联网平台',
    ruleId: 'java/path-traversal',
    ruleName: '路径遍历',
    severity: 'medium',
    confidence: 'medium',
    status: 'confirmed',
    filePath: 'src/main/java/com/fastbee/utils/FileUtils.java',
    startLine: 78,
    endLine: 80,
    startColumn: 10,
    endColumn: 45,
    codeSnippet: 'File file = new File(baseDir + "/" + filename);',
    message: '可能存在路径遍历漏洞',
    description: '用户输入直接用于文件路径可能导致目录遍历攻击',
    dataFlow: [],
    detectedAt: '2026-02-15 14:30:25',
    updatedAt: '2026-02-16 10:20:00',
    llmAnalysis: {
      isVulnerability: true,
      confidence: 0.7,
      reasoning: '用户输入未经过滤直接用于文件路径构造',
      suggestion: '使用 canonicalPath 进行路径规范化并验证路径在允许范围内',
      cwe: 'CWE-22',
    },
  },
  {
    id: 'v3',
    projectId: '2',
    projectName: 'redis C 源码',
    ruleId: 'cpp/buffer-overflow',
    ruleName: '缓冲区溢出',
    severity: 'critical',
    confidence: 'high',
    status: 'new',
    filePath: 'src/anet.c',
    startLine: 256,
    endLine: 260,
    startColumn: 3,
    endColumn: 50,
    codeSnippet: 'memcpy(dest, src, len);',
    message: '可能的缓冲区溢出',
    description: '使用 memcpy 时未验证源数据大小',
    dataFlow: [],
    detectedAt: '2026-02-18 09:15:45',
    updatedAt: '2026-02-18 09:15:45',
  },
  {
    id: 'v4',
    projectId: '3',
    projectName: 'ChanCMS',
    ruleId: 'js/xss',
    ruleName: '跨站脚本 (XSS)',
    severity: 'high',
    confidence: 'low',
    status: 'false_positive',
    filePath: 'app/controllers/article.js',
    startLine: 89,
    endLine: 91,
    startColumn: 8,
    endColumn: 35,
    codeSnippet: 'res.send("<div>" + userInput + "</div>");',
    message: '可能的 XSS 漏洞',
    description: '用户输入直接输出到 HTML 页面',
    dataFlow: [],
    detectedAt: '2026-02-10 16:20:33',
    updatedAt: '2026-02-11 11:30:00',
    llmAnalysis: {
      isVulnerability: false,
      confidence: 0.3,
      reasoning: '该代码在服务端渲染且内容经过框架默认转义',
      suggestion: '确认是否需要在客户端进行额外转义',
    },
  },
];

const severityOptions = [
  { value: 'critical', label: '严重', color: SEVERITY_COLORS.critical },
  { value: 'high', label: '高危', color: SEVERITY_COLORS.high },
  { value: 'medium', label: '中危', color: SEVERITY_COLORS.medium },
  { value: 'low', label: '低危', color: SEVERITY_COLORS.low },
  { value: 'info', label: '信息', color: SEVERITY_COLORS.info },
];

const statusOptions = [
  { value: 'new', label: '新发现', color: 'blue' },
  { value: 'confirmed', label: '已确认', color: 'red' },
  { value: 'false_positive', label: '误报', color: 'green' },
  { value: 'fixed', label: '已修复', color: 'default' },
  { value: 'ignored', label: '已忽略', color: 'default' },
];

const Vulnerabilities = () => {
  const [vulnerabilities, setVulnerabilities] = useState(mockVulnerabilities);
  const [searchText, setSearchText] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [selectedProject, setSelectedProject] = useState<string>('all');
  const [drawerVisible, setDrawerVisible] = useState(false);
  const [selectedVulnerability, setSelectedVulnerability] = useState<Vulnerability | null>(null);

  // 过滤漏洞
  const filteredVulnerabilities = vulnerabilities.filter(vuln => {
    const matchesSearch = 
      vuln.ruleName.toLowerCase().includes(searchText.toLowerCase()) ||
      vuln.filePath.toLowerCase().includes(searchText.toLowerCase()) ||
      vuln.message.toLowerCase().includes(searchText.toLowerCase());
    const matchesSeverity = selectedSeverity === 'all' || vuln.severity === selectedSeverity;
    const matchesStatus = selectedStatus === 'all' || vuln.status === selectedStatus;
    const matchesProject = selectedProject === 'all' || vuln.projectId === selectedProject;
    return matchesSearch && matchesSeverity && matchesStatus && matchesProject;
  });

  // 统计数据
  const stats = {
    total: vulnerabilities.length,
    critical: vulnerabilities.filter(v => v.severity === 'critical').length,
    high: vulnerabilities.filter(v => v.severity === 'high').length,
    medium: vulnerabilities.filter(v => v.severity === 'medium').length,
    low: vulnerabilities.filter(v => v.severity === 'low').length,
    new: vulnerabilities.filter(v => v.status === 'new').length,
  };

  // 表格列定义
  const columns: ColumnsType<Vulnerability> = [
    {
      title: '严重程度',
      dataIndex: 'severity',
      key: 'severity',
      width: 100,
      render: (severity: Severity) => (
        <Tag color={SEVERITY_COLORS[severity]}>
          {SEVERITY_LABELS[severity]}
        </Tag>
      ),
      filters: severityOptions.map(s => ({ text: s.label, value: s.value })),
      onFilter: (value, record) => record.severity === value,
    },
    {
      title: '漏洞类型',
      dataIndex: 'ruleName',
      key: 'ruleName',
      render: (text, record) => (
        <div>
          <div style={{ fontWeight: 500 }}>{text}</div>
          <div style={{ fontSize: 12, color: '#666' }}>{record.ruleId}</div>
        </div>
      ),
    },
    {
      title: '项目',
      dataIndex: 'projectName',
      key: 'projectName',
      width: 180,
      render: (text) => <Tag>{text}</Tag>,
    },
    {
      title: '位置',
      dataIndex: 'filePath',
      key: 'filePath',
      render: (text, record) => (
        <Tooltip title={text}>
          <div style={{ maxWidth: 250, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            <BugOutlined style={{ marginRight: 4 }} />
            {record.filePath}:{record.startLine}
          </div>
        </Tooltip>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (status: VulnerabilityStatus) => (
        <Tag color={statusOptions.find(s => s.value === status)?.color}>
          {STATUS_LABELS[status]}
        </Tag>
      ),
    },
    {
      title: 'LLM分析',
      key: 'llm',
      width: 100,
      render: (_, record) => (
        record.llmAnalysis ? (
          record.llmAnalysis.isVulnerability ? (
            <Tooltip title="LLM 确认是漏洞">
              <Badge status="error" />
            </Tooltip>
          ) : (
            <Tooltip title="LLM 判定为误报">
              <Badge status="success" />
            </Tooltip>
          )
        ) : (
          <Tooltip title="未进行 LLM 分析">
            <Badge status="warning" />
          </Tooltip>
        )
      ),
    },
    {
      title: '操作',
      key: 'action',
      width: 150,
      render: (_, record) => (
        <Space>
          <Tooltip title="查看详情">
            <Button
              type="link"
              size="small"
              icon={<EyeOutlined />}
              onClick={() => {
                setSelectedVulnerability(record);
                setDrawerVisible(true);
              }}
            >
              详情
            </Button>
          </Tooltip>
        </Space>
      ),
    },
  ];

  return (
    <div className="vulnerabilities-page">
      <div className="page-header">
        <Title level={3}>漏洞列表</Title>
        <Paragraph type="secondary">
          查看和管理所有检测到的安全漏洞
        </Paragraph>
      </div>

      {/* 统计卡片 */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title="总漏洞数"
              value={stats.total}
              prefix={<SafetyOutlined />}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title="严重"
              value={stats.critical}
              valueStyle={{ color: SEVERITY_COLORS.critical }}
              prefix={<WarningOutlined />}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title="高危"
              value={stats.high}
              valueStyle={{ color: SEVERITY_COLORS.high }}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title="待处理"
              value={stats.new}
              prefix={<ExclamationCircleOutlined />}
              valueStyle={{ color: '#1890ff' }}
            />
          </Card>
        </Col>
      </Row>

      {/* 筛选栏 */}
      <Card style={{ marginBottom: 24 }}>
        <Row gutter={[16, 16]} align="middle">
          <Col xs={24} sm={12} md={6}>
            <Search
              placeholder="搜索漏洞"
              allowClear
              onSearch={(value) => setSearchText(value)}
              style={{ width: '100%' }}
            />
          </Col>
          <Col xs={12} sm={6} md={3}>
            <Select
              placeholder="严重程度"
              style={{ width: '100%' }}
              value={selectedSeverity}
              onChange={setSelectedSeverity}
            >
              <Option value="all">所有严重程度</Option>
              {severityOptions.map(s => (
                <Option key={s.value} value={s.value}>
                  {s.label}
                </Option>
              ))}
            </Select>
          </Col>
          <Col xs={12} sm={6} md={3}>
            <Select
              placeholder="状态"
              style={{ width: '100%' }}
              value={selectedStatus}
              onChange={setSelectedStatus}
            >
              <Option value="all">所有状态</Option>
              {statusOptions.map(s => (
                <Option key={s.value} value={s.value}>
                  {s.label}
                </Option>
              ))}
            </Select>
          </Col>
          <Col xs={24} sm={24} md={6} style={{ textAlign: 'right' }}>
            <Space>
              <Button icon={<DownloadOutlined />}>导出</Button>
              <Button icon={<FilterOutlined />}>筛选</Button>
            </Space>
          </Col>
        </Row>
      </Card>

      {/* 漏洞列表 */}
      <Card>
        <Table
          columns={columns}
          dataSource={filteredVulnerabilities}
          rowKey="id"
          pagination={{ pageSize: 15 }}
        />
      </Card>

      {/* 漏洞详情抽屉 */}
      <Drawer
        title="漏洞详情"
        placement="right"
        width={600}
        open={drawerVisible}
        onClose={() => setDrawerVisible(false)}
      >
        {selectedVulnerability && (
          <div>
            <Descriptions column={1} bordered size="small">
              <Descriptions.Item label="漏洞类型">
                <Tag color={SEVERITY_COLORS[selectedVulnerability.severity]}>
                  {selectedVulnerability.ruleName}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="严重程度">
                {SEVERITY_LABELS[selectedVulnerability.severity]}
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                <Tag color={statusOptions.find(s => s.value === selectedVulnerability.status)?.color}>
                  {STATUS_LABELS[selectedVulnerability.status]}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="文件位置">
                {selectedVulnerability.filePath}:{selectedVulnerability.startLine}
              </Descriptions.Item>
              <Descriptions.Item label="置信度">
                {CONFIDENCE_LABELS[selectedVulnerability.confidence]}
              </Descriptions.Item>
            </Descriptions>

            <Divider>问题代码</Divider>
            <pre
              style={{
                background: '#f5f5f5',
                padding: 12,
                borderRadius: 6,
                overflow: 'auto',
                fontSize: 12,
              }}
            >
              {selectedVulnerability.codeSnippet}
            </pre>

            <Divider>详细描述</Divider>
            <Paragraph>
              {selectedVulnerability.message}
            </Paragraph>
            <Paragraph type="secondary">
              {selectedVulnerability.description}
            </Paragraph>

            {selectedVulnerability.llmAnalysis && (
              <>
                <Divider>LLM 分析结果</Divider>
                <Alert
                  message={selectedVulnerability.llmAnalysis.isVulnerability ? '可能存在安全漏洞' : '可能为误报'}
                  description={
                    <div>
                      <p><strong>置信度：</strong>{Math.round(selectedVulnerability.llmAnalysis.confidence * 100)}%</p>
                      <p><strong>分析理由：</strong>{selectedVulnerability.llmAnalysis.reasoning}</p>
                      <p><strong>修复建议：</strong>{selectedVulnerability.llmAnalysis.suggestion}</p>
                      {selectedVulnerability.llmAnalysis.cwe && (
                        <p><strong>CWE：</strong>{selectedVulnerability.llmAnalysis.cwe}</p>
                      )}
                    </div>
                  }
                  type={selectedVulnerability.llmAnalysis.isVulnerability ? 'error' : 'success'}
                  showIcon
                />
              </>
            )}

            <Divider>操作</Divider>
            <Space>
              <Button type="primary" icon={<CheckCircleOutlined />}>
                确认漏洞
              </Button>
              <Button icon={<CloseCircleOutlined />}>
                标记误报
              </Button>
            </Space>
          </div>
        )}
      </Drawer>
    </div>
  );
};

export default Vulnerabilities;
