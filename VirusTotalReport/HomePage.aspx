<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="HomePage.aspx.cs" Inherits="VirusTotalReport.HomePage" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title></title>
</head>
<body>
    <form id="form1" runat="server">
        <div>
            <asp:Table ID="tblMain" runat="server">
                <asp:TableRow>
                    <asp:TableCell>
                        <asp:Label ID="lblAPK" runat="server" Text="APK File"></asp:Label>
                    </asp:TableCell>
                </asp:TableRow>
                <asp:TableRow>
                    <asp:TableCell>
                        <asp:TextBox ID="txtAPK" runat="server" Width="300px"></asp:TextBox>
                        <asp:FileUpload ID="APKFileUpload" runat="server" />
                    </asp:TableCell>
                </asp:TableRow>

                <asp:TableRow>
                    <asp:TableCell>
                        <asp:Label ID="lblDexFile" runat="server" Text="DEX File"></asp:Label>
                    </asp:TableCell>
                </asp:TableRow>
                <asp:TableRow>
                    <asp:TableCell>
                        <asp:TextBox ID="txtDEX" runat="server" Width="300px"></asp:TextBox>
                        <%--<asp:FileUpload ID="DEXFileUpload" runat="server" />--%>
                    </asp:TableCell>
                </asp:TableRow>

                <asp:TableRow>
                    <asp:TableCell>
                        <asp:Label ID="lblOATFile" runat="server" Text="OAT File"></asp:Label>
                    </asp:TableCell>
                </asp:TableRow>
                <asp:TableRow>
                    <asp:TableCell>
                        <asp:TextBox ID="txtOAT" runat="server" Width="300px"></asp:TextBox>
                        <%--<asp:FileUpload ID="OATFileUpload" runat="server" />--%>
                    </asp:TableCell>
                </asp:TableRow>

                <asp:TableRow>
                    <asp:TableCell ColumnSpan="2" HorizontalAlign="Center">
                        <asp:TableCell>
                        <asp:Button ID="btnGenerateReport" runat="server" Text="Generate Report" OnClick="btnGenerateReport_Click" />
                    </asp:TableCell>
                    </asp:TableCell>
                </asp:TableRow>


                <asp:TableRow>
                    <asp:TableCell ColumnSpan="2" HorizontalAlign="Center">
                        <asp:TextBox ID="txtResults" runat="server" TextMode="MultiLine" Height="300px" Width="500px"></asp:TextBox>
                    </asp:TableCell>
                </asp:TableRow>

                <asp:TableRow>
                    <asp:TableCell ColumnSpan="2" HorizontalAlign="Center">
                        <asp:Button ID="btnSave" runat="server" Text="Save Report" OnClick="btnSave_Click" />
                    </asp:TableCell>
                </asp:TableRow>

                </asp:Table>
        </div>
    </form>
</body>
</html>
