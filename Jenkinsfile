node {
    try {
        stage 'Code Quality'

        deleteDir()
        
        checkout scm

        def workspace = pwd() 
        def version = env.BRANCH_NAME

        if(env.BRANCH_NAME=="master") {
            version = sh(returnStdout: true, script: 'git describe --abbrev=0 --tags').trim()
            checkout([$class: 'GitSCM', branches: [[name: "tags/${version}"]], extensions: [[$class: 'CleanCheckout']]])
        }
        
        sh("./build.sh")

        stage 'Notifier'
        build job: 'notifier', parameters: [[$class: 'StringParameterValue', name: 'message', value: "${env.JOB_NAME} succeeded: see [Jenkins job ${env.BUILD_ID}](${env.BUILD_URL})"]] 
    }
    catch(error) {
        build job: 'notifier', parameters: [[$class: 'StringParameterValue', name: 'message', value: "${env.JOB_NAME} failed: see [Jenkins job ${env.BUILD_ID}](${env.BUILD_URL})"]]
        currentBuild.result = "FAILED"
        throw error
    }
}
