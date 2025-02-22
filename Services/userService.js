const sql = require('mssql');
const dbConfig = require("../dbConfig");
const SaveResponse = require("../Shared/SaveResponse");

async function getUsers() {
    try {
        await sql.connect(dbConfig);
        const result = await sql.query("SELECT * FROM Users_NotDeleted");
        return result.recordset;
    } catch (err) {
        throw new Error(err.message);
    }
}

async function saveUser(user) {
    try {
        
        const { UserName, UserID, Email, Password, ConfirmPassword, Role,ImageURL, IsActive } = user;
        await sql.connect(dbConfig);

         // Prepare the request for the stored procedure
         const request = new sql.Request();
        const Response ='';
         // Add parameters to the request
         request.input('UserName', sql.NVarChar, UserName);
         request.input('UserID', sql.Int, UserID);
         request.input('Email', sql.NVarChar, Email);
         request.input('Password', sql.NVarChar, Password);
         request.input('ImageURL', sql.NVarChar, ImageURL);
         request.input('Role', sql.NVarChar, Role);
         request.input('IsActive', sql.Bit, IsActive);
         request.output('Response',sql.NVarChar,Response);
 
         // Execute the stored procedure
         const result = await request.execute('SaveUser');

         const Resp = new SaveResponse();
         Resp.ID =result.output.Response;
         Resp.Status ='success';
         Resp.Saved =true;
         // Return the result from the stored procedure
         console.log(Resp);
         
         return Resp;
    } catch (err) {
        throw new Error(err.message);
    }
}


async function AuthenticateUser(user) {
    try {
        
        const {  Email, Password , Role} = user;

        await sql.connect(dbConfig);

        const request = new sql.Request();
        
        request.input('Email', sql.NVarChar, Email);
        request.input('Password', sql.NVarChar, Password);
        request.input('Role', sql.Int, Role);
        const Response ='';
        request.output('Response',sql.NVarChar,Response);
 
        const result = await request.execute('AuthenticateUser');

        const Resp = new SaveResponse();

        if(result.recordset.length>0){
            Resp.Status ='success';
            Resp.Saved =true;
            Resp.ID =result.output.Response;
        }else{
            Resp.Status ='failed';
            Resp.Saved =false;
        }

        console.log(Resp);
         
        return Resp;

    } catch (err) {
        throw new Error(err.message);
    }
}

async function GetUserDetails(UserID) {
    try {
        await sql.connect(dbConfig);
        const request = new sql.Request();
        request.input('UserID', sql.Int, UserID);
        console.log(UserID);
       
        const result = await request.execute("GetUserDetails");
        return result.recordset;
    } catch (err) {
        throw new Error(err.message);
    }
}


async function DeleteUser(UserID) {
    try {
        await sql.connect(dbConfig);
        const request = new sql.Request();

        request.input('UserID', sql.Int, UserID);
const Response ='';
        request.output('Response',sql.NVarChar,Response);
        const result = await request.execute("DeleteUser");
return result.output.Response;
         
    } catch (err) {
       
        throw new Error(err.message);
    }
}


module.exports = {
    getUsers, saveUser, AuthenticateUser ,GetUserDetails,DeleteUser
};
