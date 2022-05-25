// const {
//     createPool
// } = require('mysql');

// const pool = createPool({
//     host:"localhost",
//     user:"root",
//     password:"password",
//     database:"userlogin",
//     //connectionLimit:10
// })

// // get rsa token number
// // now write software that performs the aes (pretend you are maxdavid) (in eclipse: by taking the current time and seed from database)
// // outputs result here and puts it centered on a website


// pool.query('SELECT * FROM masterseed', (err, result, field)=>{
//     if(err){
//         return console.log(err);
//     }
//     return console.log(result);
// })


//const http = require('http')
//const port = 8080

// make sure you go to "I changed the compiler jdk compliance. In Eclipse its under (click on the entire project name)
// project properties > java compiler > jdk compliance"
// change from 13 to 1.8

// this token is for user "maxdavid", who has this seed number
// seed is stored in the token
const seed = '4gk6txq2f9c974px';

//const tokenEl = document.getElementById('tokenVal');
setInterval(updateToken, 1000);

function updateToken(){

let date1 = new Date("01/01/1986");
let date2 = Date.now();
let currTime = Math.floor((date2-date1)/1000)//subtract 5 hours bc ot utc time;

var child = require('child_process').spawn(
    'java', ['-jar', 'aes.jar', seed, currTime]
);
let string1 = "";
child.stdout.on('data', function(data) {
    string1 = data.toString();
    
    console.log(string1);
    console.log(currTime);
});

child.stderr.on("data", function (data) {
    string1 = data.toString();
    console.log(string1);
});
//tokenEl.innerHTML = `hi`;
}
// const server = http.createServer(function(req, res){
//     res.write(string1);
//     res.end();
// })
