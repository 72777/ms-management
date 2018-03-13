pipeline {
  agent any
  options {
    buildDiscarder(logRotator(numToKeepStr:'10'))
  }
  environment {
    APP_PROJECT = 'management'
    DOCKER_REGISTRY = 'docker.factioninc.com'
    DOCKER_IMAGE = "${APP_PROJECT}:${GIT_COMMIT}"
    DOCKER_ARTIFACT = "${DOCKER_REGISTRY}/${DOCKER_IMAGE}"
  }
  stages {
    stage('Checkout') {
      steps {
        echo 'Checking out code from GitHub'
      }
    }
    stage('Build Image') {
      steps {
        sh 'docker build -t ${DOCKER_IMAGE} .'
      }
    }
    stage('Unit Tests') {
      post {
        always {
          junit 'unit_test.xml'
        }
      }
      steps {
        sh 'docker run --rm -v ${WORKSPACE}:/tmp ${DOCKER_IMAGE} /usr/src/app/tests/tests.sh'
      }
    }
    stage('Micro-Integration Tests') {
      steps {
        echo 'Run localized docker testing here to validate communication functionality'
      }
    }
    stage('Push to Docker Repository') {
      steps {
        sh 'docker tag ${DOCKER_IMAGE} ${DOCKER_ARTIFACT}'
        sh 'docker push $DOCKER_ARTIFACT'
      }
    }
    stage('Deploy to Kubernetes DEV') {
        when {
            branch 'develop'
        }
        post {
          success {
              build 'tests-public-api/develop'
          }
        }
        steps {
            sh 'kubectl --kubeconfig=${JENKINS_HOME}/kubeconfig/${GIT_BRANCH}/kubeconfig.yml set image deployment ${APP_PROJECT} ${APP_PROJECT}=${DOCKER_ARTIFACT}'
        }
    }
  }
  post {
    always {
      sh 'docker images ${APP_PROJECT} -qf before=${DOCKER_IMAGE} | xargs -r docker rmi -f'
      sh 'docker images --filter "dangling=true" -q --no-trunc | xargs -r docker rmi -f'
      deleteDir()
      script {
        def notifier = new jenkins.slack.SlackNotifier()
        notifier.notifyResultFull()
      }
    }
  }
}