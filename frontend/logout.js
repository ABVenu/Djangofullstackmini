// logout.js

export default function logout(csrftoken,jwt) {
    // Remove the JWT token from local storage
    fetch('http://127.0.0.1:8000/blogs/logout',{
        method:"POST",
        headers: {
            "X-CSRFToken": csrftoken,
            "Authorization": `Bearer ${jwt}`,
          },
    }).then((res)=>res.json())
    .then((data)=>{
        console.log(data)
        localStorage.removeItem("jwt")
        alert(data.data)
    }).catch((err)=>{
        console.log(err)
    })
    
  }
  

async function getData(){
    let data = fetch("https://masai-course.s3.ap-south-1.amazonaws.com/editor/uploads/2023-09-12/MOCK_DATA_277992.json")
}