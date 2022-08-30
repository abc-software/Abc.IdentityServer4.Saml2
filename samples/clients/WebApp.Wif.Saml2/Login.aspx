<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Login.aspx.cs" Inherits="Samples.Saml.ServiceProvider.Login" %>

<%@ OutputCache Location="None" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title>Service Provider - Unauthenticated</title>
</head>
<body>
    <form id="form1" runat="server">
    <div>
        <asp:Label ID="ErrorLabel" runat="server" Text="" Visible="false" Font-Size="Large"
            ForeColor="DarkRed"></asp:Label>
    </div>
    <div style="font-size: x-large; font-weight: bold">
        Windows Identity Foundation - SAML Service Provider
    </div>
    <div>
        <br />
        You are not logged in. Click here to login:<br />    
        <asp:Button ID="LoginButton" runat="server" Text="Login" OnClick="Login_Click" />
    </div>
    </form>
</body>
</html>
