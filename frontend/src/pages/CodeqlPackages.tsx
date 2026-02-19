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
  Modal,
  Form,
  message,
  Popconfirm,
  Tooltip,
  Tabs,
  Badge,
  Switch,
  Alert,
  Avatar,
  Statistic,
} from 'antd';
import {
  AppstoreOutlined,
  BookOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  DeleteOutlined,
  DownloadOutlined,
  EditOutlined,
  FolderOutlined,
  InfoCircleOutlined,
  SyncOutlined,
  UploadOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import type { CodeqlPackage, ProgrammingLanguage } from '../types';
import { LANGUAGE_LABELS } from '../types';
import '../styles/Page.css';

const { Title, Paragraph, Text } = Typography;
const { Search } = Input;
const { Option } = Select;
const { TextArea } = Input;

// 模拟官方 CodeQL 包数据
const officialPackages: CodeqlPackage[] = [
  {
    id: 'codeql/java',
    name: 'Java CodeQL 包',
    type: 'official',
    language: 'java',
    description: 'GitHub 官方 Java 安全查询库',
    path: 'codeql/java',
    queryCount: 156,
    isEnabled: true,
    version: '1.0.0',
    author: 'GitHub',
    source: 'https://github.com/github/codeql',
    createdAt: '2024-01-01',
    updatedAt: '2024-12-01',
  },
  {
    id: 'codeql/cpp',
    name: 'C/C++ CodeQL 包',
    type: 'official',
    language: 'cpp',
    description: 'GitHub 官方 C/C++ 安全查询库',
    path: 'codeql/cpp',
    queryCount: 203,
    isEnabled: true,
    version: '1.0.0',
    author: 'GitHub',
    source: 'https://github.com/github/codeql',
    createdAt: '2024-01-01',
    updatedAt: '2024-12-01',
  },
  {
    id: 'codeql/javascript',
    name: 'JavaScript/TypeScript CodeQL 包',
    type: 'official',
    language: 'javascript',
    description: 'GitHub 官方 JavaScript/TypeScript 安全查询库',
    path: 'codeql/javascript',
    queryCount: 178,
    isEnabled: true,
    version: '1.0.0',
    author: 'GitHub',
    source: 'https://github.com/github/codeql',
    createdAt: '2024-01-01',
    updatedAt: '2024-12-01',
  },
  {
    id: 'codeql/csharp',
    name: 'C# CodeQL 包',
    type: 'official',
    language: 'csharp',
    description: 'GitHub 官方 C# 安全查询库',
    path: 'codeql/csharp',
    queryCount: 142,
    isEnabled: true,
    version: '1.0.0',
    author: 'GitHub',
    source: 'https://github.com/github/codeql',
    createdAt: '2024-01-01',
    updatedAt: '2024-12-01',
  },
  {
    id: 'codeql/python',
    name: 'Python CodeQL 包',
    type: 'official',
    language: 'python',
    description: 'GitHub 官方 Python 安全查询库',
    path: 'codeql/python',
    queryCount: 98,
    isEnabled: true,
    version: '1.0.0',
    author: 'GitHub',
    source: 'https://github.com/github/codeql',
    createdAt: '2024-01-01',
    updatedAt: '2024-12-01',
  },
  {
    id: 'codeql/go',
    name: 'Go CodeQL 包',
    type: 'official',
    language: 'go',
    description: 'GitHub 官方 Go 安全查询库',
    path: 'codeql/go',
    queryCount: 87,
    isEnabled: true,
    version: '1.0.0',
    author: 'GitHub',
    source: 'https://github.com/github/codeql',
    createdAt: '2024-01-01',
    updatedAt: '2024-12-01',
  },
];

// 模拟社区 CodeQL 包数据
const communityPackages: CodeqlPackage[] = [
  {
    id: 'amnt/security-queries',
    name: '高级安全查询',
    type: 'community',
    language: 'java',
    description: '社区维护的高级安全漏洞检测查询',
    path: 'amnt/security-queries',
    queryCount: 45,
    isEnabled: true,
    version: '2.3.0',
    author: 'AMNT',
    source: 'https://github.com/AMNT-Company/codeql-security-queries',
    createdAt: '2024-03-15',
    updatedAt: '2024-11-20',
  },
  {
    id: 'semmle/external',
    name: '外部查询库',
    type: 'community',
    language: 'cpp',
    description: 'Semmle 社区共享的外部控制流检测查询',
    path: 'semmle/external',
    queryCount: 23,
    isEnabled: false,
    version: '1.5.0',
    author: 'Semmle',
    source: 'https://github.com/Semmle/ql',
    createdAt: '2024-02-10',
    updatedAt: '2024-10-05',
  },
];

// 模拟自定义 CodeQL 包数据
const customPackages: CodeqlPackage[] = [
  {
    id: 'custom/my-rules',
    name: '我的自定义规则',
    type: 'custom',
    language: 'java',
    description: '项目特定的自定义安全规则',
    path: 'D:/codeql-rules/my-rules',
    queryCount: 12,
    isEnabled: true,
    version: '1.0.0',
    author: '本地',
    source: '本地文件系统',
    createdAt: '2024-06-01',
    updatedAt: '2024-09-15',
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

const CodeqlPackages = () => {
  const [activeTab, setActiveTab] = useState<string>('official');
  const [searchText, setSearchText] = useState('');
  const [selectedLanguage, setSelectedLanguage] = useState<string>('all');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [form] = Form.useForm();

  // 根据当前Tab显示不同的包
  const getPackages = (): CodeqlPackage[] => {
    let packages: CodeqlPackage[] = [];
    switch (activeTab) {
      case 'official':
        packages = officialPackages;
        break;
      case 'community':
        packages = communityPackages;
        break;
      case 'custom':
        packages = customPackages;
        break;
      default:
        packages = [];
    }
    return packages;
  };

  // 过滤包
  const filteredPackages = getPackages().filter(pkg => {
    const matchesSearch = pkg.name.toLowerCase().includes(searchText.toLowerCase()) ||
                         pkg.description.toLowerCase().includes(searchText.toLowerCase());
    const matchesLanguage = selectedLanguage === 'all' || pkg.language === selectedLanguage;
    return matchesSearch && matchesLanguage;
  });

  // 获取状态标签
  const getTypeTag = (type: string) => {
    const config: Record<string, { color: string; text: string; icon: React.ReactNode }> = {
      official: { color: 'blue', text: '官方', icon: <BookOutlined /> },
      community: { color: 'green', text: '社区', icon: <AppstoreOutlined /> },
      custom: { color: 'orange', text: '自定义', icon: <FolderOutlined /> },
    };
    const tag = config[type] || { color: 'default', text: type, icon: null };
    return (
      <Tag color={tag.color} icon={tag.icon}>
        {tag.text}
      </Tag>
    );
  };

  // 表格列定义
  const columns: ColumnsType<CodeqlPackage> = [
    {
      title: '包名称',
      dataIndex: 'name',
      key: 'name',
      render: (text, record) => (
        <Space>
          <Avatar
            size="small"
            style={{
              backgroundColor: record.type === 'official' ? '#1890ff' :
                             record.type === 'community' ? '#52c41a' : '#fa8c16'
            }}
            icon={<BookOutlined />}
          />
          <div>
            <div style={{ fontWeight: 500 }}>{text}</div>
            <div style={{ fontSize: 12, color: '#666' }}>{record.id}</div>
          </div>
        </Space>
      ),
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      width: 100,
      render: (type) => getTypeTag(type),
    },
    {
      title: '语言',
      dataIndex: 'language',
      key: 'language',
      width: 140,
      render: (lang: ProgrammingLanguage) => (
        <Tag>{LANGUAGE_LABELS[lang]}</Tag>
      ),
    },
    {
      title: '查询数量',
      dataIndex: 'queryCount',
      key: 'queryCount',
      width: 100,
      render: (count) => <Badge count={count} showZero color="#1890ff" />,
    },
    {
      title: '版本',
      dataIndex: 'version',
      key: 'version',
      width: 80,
      render: (version) => <Text code>v{version}</Text>,
    },
    {
      title: '描述',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true,
    },
    {
      title: '状态',
      dataIndex: 'isEnabled',
      key: 'isEnabled',
      width: 80,
      render: (enabled, record) => (
        <Tooltip title={enabled ? '已启用' : '已禁用'}>
          <Switch
            checked={enabled}
            checkedChildren={<CheckCircleOutlined />}
            unCheckedChildren={<CloseCircleOutlined />}
            onChange={(checked) => {
              message.success(`${record.name} 已${checked ? '启用' : '禁用'}`);
            }}
          />
        </Tooltip>
      ),
    },
    {
      title: '操作',
      key: 'action',
      width: 150,
      render: (_, record) => (
        <Space size="small">
          <Tooltip title="查看详情">
            <Button
              type="text"
              size="small"
              icon={<InfoCircleOutlined />}
              onClick={() => message.info('查看详情功能开发中')}
            />
          </Tooltip>
          {record.type === 'custom' && (
            <>
              <Tooltip title="编辑">
                <Button
                  type="text"
                  size="small"
                  icon={<EditOutlined />}
                  onClick={() => {
                    form.setFieldsValue(record);
                    setIsModalOpen(true);
                  }}
                />
              </Tooltip>
              <Popconfirm
                title="确定要删除这个包吗？"
                onConfirm={() => message.success('包已删除')}
              >
                <Tooltip title="删除">
                  <Button
                    type="text"
                    size="small"
                    danger
                    icon={<DeleteOutlined />}
                  />
                </Tooltip>
              </Popconfirm>
            </>
          )}
          {record.type !== 'official' && (
            <Tooltip title="下载更新">
              <Button
                type="text"
                size="small"
                icon={<DownloadOutlined />}
                onClick={() => message.info('检查更新...')}
              />
            </Tooltip>
          )}
        </Space>
      ),
    },
  ];

  // Tab 内容
  const tabItems = [
    {
      key: 'official',
      label: (
        <span>
          <BookOutlined /> 官方包
        </span>
      ),
      children: (
        <Table
          columns={columns}
          dataSource={filteredPackages}
          rowKey="id"
          pagination={{ pageSize: 10 }}
        />
      ),
    },
    {
      key: 'community',
      label: (
        <span>
          <AppstoreOutlined /> 社区包
        </span>
      ),
      children: (
        <Table
          columns={columns}
          dataSource={filteredPackages}
          rowKey="id"
          pagination={{ pageSize: 10 }}
        />
      ),
    },
    {
      key: 'custom',
      label: (
        <span>
          <FolderOutlined /> 自定义包
        </span>
      ),
      children: (
        <Table
          columns={columns}
          dataSource={filteredPackages}
          rowKey="id"
          pagination={{ pageSize: 10 }}
        />
      ),
    },
  ];

  // 统计信息
  const stats = {
    official: officialPackages.length,
    community: communityPackages.length,
    custom: customPackages.length,
    totalQueries: [...officialPackages, ...communityPackages, ...customPackages]
      .reduce((sum, pkg) => sum + pkg.queryCount, 0),
  };

  // 处理添加自定义包
  const handleAddCustomPackage = () => {
    form.resetFields();
    form.setFieldsValue({
      isEnabled: true,
      language: 'java',
    });
    setIsModalOpen(true);
  };

  // 处理表单提交
  const handleSubmit = () => {
    form.validateFields().then(values => {
      message.success('包添加成功');
      setIsModalOpen(false);
    });
  };

  return (
    <div className="packages-page">
      <div className="page-header">
        <Title level={3}>CodeQL 包管理</Title>
        <Paragraph type="secondary">
          管理 CodeQL 查询包，包括官方包、社区包和自定义包
        </Paragraph>
      </div>

      {/* 统计卡片 */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="官方包"
              value={stats.official}
              prefix={<BookOutlined />}
              valueStyle={{ color: '#1890ff' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="社区包"
              value={stats.community}
              prefix={<AppstoreOutlined />}
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="自定义包"
              value={stats.custom}
              prefix={<FolderOutlined />}
              valueStyle={{ color: '#fa8c16' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="总查询数"
              value={stats.totalQueries}
              prefix={<FolderOutlined />}
              valueStyle={{ color: '#722ed1' }}
            />
          </Card>
        </Col>
      </Row>

      {/* 操作栏 */}
      <Card style={{ marginBottom: 24 }}>
        <Row gutter={[16, 16]} align="middle">
          <Col xs={24} sm={12} md={8}>
            <Search
              placeholder="搜索包名称或描述"
              allowClear
              onSearch={(value) => setSearchText(value)}
              onChange={(e) => setSearchText(e.target.value)}
              style={{ width: '100%' }}
            />
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Select
              placeholder="筛选语言"
              style={{ width: '100%' }}
              value={selectedLanguage}
              onChange={setSelectedLanguage}
            >
              <Option value="all">所有语言</Option>
              {languageOptions.map(lang => (
                <Option key={lang.value} value={lang.value}>
                  {lang.label}
                </Option>
              ))}
            </Select>
          </Col>
          <Col xs={24} sm={24} md={10} style={{ textAlign: 'right' }}>
            <Space>
              <Button icon={<SyncOutlined />}>检查更新</Button>
              <Button
                type="primary"
                icon={<UploadOutlined />}
                onClick={handleAddCustomPackage}
              >
                添加自定义包
              </Button>
            </Space>
          </Col>
        </Row>
      </Card>

      {/* 包列表 */}
      <Card>
        <Tabs
          activeKey={activeTab}
          onChange={setActiveTab}
          items={tabItems}
        />
      </Card>

      {/* 添加/编辑自定义包模态框 */}
      <Modal
        title="添加自定义 CodeQL 包"
        open={isModalOpen}
        onOk={handleSubmit}
        onCancel={() => setIsModalOpen(false)}
        width={600}
        okText="添加"
        cancelText="取消"
      >
        <Alert
          message="自定义包说明"
          description="您可以添加本地文件系统中的 CodeQL 查询包，或从 GitHub 仓库克隆的查询包。"
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
        />
        <Form
          form={form}
          layout="vertical"
          style={{ marginTop: 16 }}
        >
          <Form.Item
            name="name"
            label="包名称"
            rules={[{ required: true, message: '请输入包名称' }]}
          >
            <Input placeholder="例如：我的自定义规则" />
          </Form.Item>

          <Form.Item
            name="language"
            label="编程语言"
            rules={[{ required: true, message: '请选择编程语言' }]}
          >
            <Select placeholder="选择语言">
              {languageOptions.map(lang => (
                <Option key={lang.value} value={lang.value}>
                  {lang.label}
                </Option>
              ))}
            </Select>
          </Form.Item>

          <Form.Item
            name="source"
            label="包来源"
            rules={[{ required: true, message: '请输入包路径或 URL' }]}
            extra="可以是本地路径（如 D:/codeql-rules）或 GitHub 仓库 URL"
          >
            <Input placeholder="例如：D:/codeql-rules/my-rules 或 https://github.com/..." />
          </Form.Item>

          <Form.Item
            name="description"
            label="描述"
          >
            <TextArea rows={3} placeholder="描述这个查询包的功能" />
          </Form.Item>

          <Form.Item
            name="isEnabled"
            label="状态"
            valuePropName="checked"
          >
            <Switch checkedChildren="启用" unCheckedChildren="禁用" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default CodeqlPackages;
