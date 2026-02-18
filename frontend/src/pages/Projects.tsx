import { Typography, Card, Empty } from 'antd';
import { FolderOpenOutlined } from '@ant-design/icons';
import '../styles/Page.css';

const { Title, Paragraph } = Typography;

const Projects = () => {
  return (
    <div className="projects-page">
      <div className="page-header">
        <Title level={3}>项目管理</Title>
        <Paragraph type="secondary">
          管理待分析的代码项目和数据库
        </Paragraph>
      </div>
      <Card className="coming-soon-card">
        <Empty
          image={<FolderOpenOutlined style={{ fontSize: 64, color: '#d9d9d9' }} />}
          description={
            <div>
              <Paragraph style={{ fontSize: 16, color: 'rgba(0, 0, 0, 0.65)' }}>
                项目管理功能开发中...
              </Paragraph>
            </div>
          }
        />
      </Card>
    </div>
  );
};

export default Projects;
