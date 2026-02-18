import { Typography, Card, Empty } from 'antd';
import { SettingOutlined } from '@ant-design/icons';
import '../styles/Page.css';

const { Title, Paragraph } = Typography;

const Settings = () => {
  return (
    <div className="settings-page">
      <div className="page-header">
        <Title level={3}>设置</Title>
        <Paragraph type="secondary">
          配置 LLM、CodeQL 等系统参数
        </Paragraph>
      </div>
      <Card className="coming-soon-card">
        <Empty
          image={<SettingOutlined style={{ fontSize: 64, color: '#d9d9d9' }} />}
          description={
            <div>
              <Paragraph style={{ fontSize: 16, color: 'rgba(0, 0, 0, 0.65)' }}>
                设置功能开发中...
              </Paragraph>
            </div>
          }
        />
      </Card>
    </div>
  );
};

export default Settings;
